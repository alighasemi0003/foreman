# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
require 'tmpdir'

module Foreman
  module Console
    # Short-lived, host/VM-scoped console authorization ticket.
    # Session material (including the hypervisor VNC password) is stored
    # server-side in a mode-0600 file; only the opaque ticket id is given to
    # the browser as a WebSocket query parameter.
    class Ticket
      DEFAULT_TTL = 120
      DIR_ENV = 'FOREMAN_CONSOLE_TICKET_DIR'

      attr_reader :id, :path, :binding, :expires_at, :vnc_host, :vnc_port

      def self.store_dir
        env_dir = ENV[DIR_ENV]
        dir = (env_dir.nil? || env_dir.empty?) ? File.join(Dir.tmpdir, 'foreman-console-tickets') : env_dir
        FileUtils.mkdir_p(dir, mode: 0o700)
        File.chmod(0o700, dir) if File.directory?(dir)
        dir
      end

      def self.create!(password:, vnc_host:, vnc_port:, binding:, ttl: DEFAULT_TTL)
        id = SecureRandom.urlsafe_base64(32)
        expires_at = Time.now.to_i + Integer(ttl)
        path = File.join(store_dir, "#{id}.json")
        payload = {
          'ticket' => id,
          'binding' => binding.to_s,
          'vnc_host' => vnc_host.to_s,
          'vnc_port' => Integer(vnc_port),
          'password' => password.to_s,
          'expires_at' => expires_at,
          'used' => false,
        }
        File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
          f.write(JSON.generate(payload))
        end
        new(id: id, path: path, binding: binding.to_s, expires_at: expires_at,
            vnc_host: vnc_host.to_s, vnc_port: Integer(vnc_port), password: password.to_s)
      end

      def self.load(id, store_dir: nil)
        dir = store_dir || self.store_dir
        path = File.join(dir, "#{id}.json")
        return nil unless File.file?(path)

        data = JSON.parse(File.read(path))
        return nil unless secure_compare(data['ticket'].to_s, id.to_s)

        new(id: id, path: path, binding: data['binding'].to_s, expires_at: data['expires_at'].to_i,
            vnc_host: data['vnc_host'].to_s, vnc_port: data['vnc_port'].to_i,
            password: data['password'].to_s, used: data['used'])
      rescue Errno::ENOENT, JSON::ParserError
        nil
      end

      def initialize(id:, path:, binding:, expires_at:, vnc_host:, vnc_port:, password: nil, used: false)
        @id = id
        @path = path
        @binding = binding
        @expires_at = expires_at
        @vnc_host = vnc_host
        @vnc_port = vnc_port
        @password = password
        @used = used
      end

      attr_reader :password

      def expired?
        Time.now.to_i >= @expires_at.to_i
      end

      def used?
        !!@used
      end

      def valid_for?(binding_key = nil)
        return false if expired? || used?
        return true if binding_key.nil? || binding_key.to_s.empty?

        self.class.secure_compare(@binding, binding_key.to_s)
      end

      # Marks ticket used and returns the password for one RFB session.
      def consume!
        raise 'console ticket expired' if expired?
        raise 'console ticket already used' if used?

        data = JSON.parse(File.read(@path))
        raise 'console ticket already used' if data['used']

        password = data['password'].to_s
        data['used'] = true
        data['password'] = ''
        File.open(@path, File::WRONLY | File::TRUNC, 0o600) { |f| f.write(JSON.generate(data)) }
        @password = nil
        @used = true
        password
      end

      def destroy!
        File.unlink(@path) if @path && File.exist?(@path)
      rescue Errno::ENOENT
        nil
      end

      def self.secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        result = 0
        a.bytes.zip(b.bytes) { |x, y| result |= x ^ y }
        result.zero?
      end
    end
  end
end
