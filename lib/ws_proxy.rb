# frozen_string_literal: true

require 'open3'
require 'socket'
require 'timeout'
require 'rbconfig'

class PortInUse < StandardError; end

class WsProxy
  attr_accessor :host, :host_port, :password, :timeout, :idle_timeout, :ssl_target,
                :rfb_auth, :binding
  attr_reader :proxy_port

  # Allowed ports to communicate with our web sockets proxy
  PORTS = 5910..5930

  def initialize(attributes)
    defaults.merge(attributes).each do |k, v|
      send("#{k}=", v) if respond_to?("#{k}=")
    end
  end

  def self.start(attributes)
    proxy = WsProxy.new(attributes)
    proxy.start_proxy
  end

  def free_port?(port)
    socket = Socket.new :INET, :STREAM
    socket.bind(Socket.pack_sockaddr_in(port, '127.0.0.1'))
    true
  rescue Errno::EADDRINUSE
    false
  ensure
    socket&.close
  end

  def start_proxy
    port = 0
    Timeout.timeout(5) do
      until free_port?(port = rand(PORTS)); end
    end

    if rfb_auth && password.to_s != ''
      start_rfb_auth_gateway(port)
    else
      start_websockify(port)
    end
  end

  private

  def defaults
    {
      :timeout => 120,
      :idle_timeout => 120,
      :host_port => 5900,
      :host => "0.0.0.0",
      :rfb_auth => false,
      :binding => nil,
    }
  end

  def logger
    Rails.logger
  end

  def start_rfb_auth_gateway(port)
    require 'foreman/console/ticket'

    ticket = nil
    begin
      ticket = Foreman::Console::Ticket.create!(
        password: password,
        vnc_host: host,
        vnc_port: host_port,
        binding: (binding.present? ? binding : "#{host}:#{host_port}"),
        ttl: timeout
      )
      execute_gateway(gateway_command(port, ticket))
    rescue PortInUse
      ticket&.destroy!
      ticket = nil
      port += 1
      raise ::Foreman::Exception.new(N_('No free ports available for VNC gateway, try again later')) if port >= PORTS.last

      retry
    rescue StandardError
      ticket&.destroy!
      raise
    end

    @proxy_port = port
    {
      :port => proxy_port,
      :password => nil,
      :encrypt => Setting[:websockets_encrypt],
      :path => "/?ticket=#{ticket.id}",
    }
  end

  def gateway_command(port, ticket)
    script = File.join(Rails.root, 'script', 'foreman-vnc-gateway')
    cmd = [
      RbConfig.ruby,
      script,
      '--daemon',
      '--port', port.to_s,
      '--ticket', ticket.id,
      '--store-dir', Foreman::Console::Ticket.store_dir,
      '--timeout', timeout.to_s,
      '--idle-timeout', idle_timeout.to_s,
    ]
    if Setting[:websockets_encrypt]
      cmd += ['--ssl-cert', Setting[:websockets_ssl_cert]] if Setting[:websockets_ssl_cert].present?
      cmd += ['--ssl-key', Setting[:websockets_ssl_key]] if Setting[:websockets_ssl_key].present?
    end
    cmd
  end

  def execute_gateway(cmd)
    port = Integer(cmd[cmd.index('--port') + 1])
    # Do not log ticket ids or display passwords (ticket appears in argv).
    logger.debug "Starting VNC RFB auth gateway on port #{port}"
    out, err, status = Open3.capture3(*cmd)
    raise PortInUse if err.to_s.include?('Address already in use') || out.to_s.include?('Address already in use')
    raise ::Foreman::Exception.new(N_('Failed to start VNC console gateway')) unless status.success?

    # Daemon parent exits before the child binds; wait briefly for the listen port.
    Timeout.timeout(5) do
      sleep 0.05 until gateway_listening?(port)
    end
  rescue Timeout::Error
    raise ::Foreman::Exception.new(N_('VNC console gateway failed to open listen port'))
  end

  def gateway_listening?(port)
    socket = TCPSocket.new('127.0.0.1', port)
    socket.close
    true
  rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH
    false
  end

  def start_websockify(port)
    begin
      cmd = ["websockify", "--daemon", "--idle-timeout=#{idle_timeout}", "--timeout=#{timeout}", port.to_s, "#{host}:#{host_port}"]
      cmd += ["--ssl-target"] if ssl_target
      if Setting[:websockets_encrypt]
        cmd += ["--cert", Setting[:websockets_ssl_cert]] if Setting[:websockets_ssl_cert]
        cmd += ["--key", Setting[:websockets_ssl_key]] if Setting[:websockets_ssl_key]
      end
      execute_websockify(cmd)
    rescue Errno::ENOENT
      raise ::Foreman::Exception.new(N_('Websockify was not found'))
    rescue PortInUse
      port += 1
      if port >= PORTS.last
        raise ::Foreman::Exception.new(N_('No free ports available for websockify, try again later'))
      else
        retry
      end
    end
    @proxy_port = port
    { :port => proxy_port, :password => password, :encrypt => Setting[:websockets_encrypt] }
  end

  def execute_websockify(cmd)
    logger.debug "Starting VNC Proxy: #{cmd.inspect}"
    Open3.popen3(*cmd) do |_stdin, stdout, stderr|
      stdout.each do |line|
        logger.debug "[#{line}"
      end
      stderr.each do |line|
        logger.debug "VNCProxy Error: #{line}"
        raise PortInUse if line["socket.error: [Errno 98] Address already in use"]
      end
    end
  end
end
