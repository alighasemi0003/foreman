# frozen_string_literal: true

require 'socket'
require 'uri'
require 'timeout'

module Foreman
  module SecurityEvent
    # Non-blocking, best-effort forwarder for structured security events (F-041).
    #
    # Delivery semantics: **at-most-once** to the collector (drops on full queue /
    # send failure). Local Rails / Audit logging is unaffected.
    #
    # Never raises into the request path. Never logs payload secrets.
    class Forwarder
      DEFAULT_QUEUE = 1000
      DEFAULT_CONNECT_TIMEOUT = 1.0
      DEFAULT_WRITE_TIMEOUT = 1.0

      class << self
        def instance
          @instance ||= new
        end

        def reset!
          @instance&.shutdown
          @instance = nil
        end

        def enabled?
          ENV.fetch('FOREMAN_SECURITY_EVENTS_ENABLED', 'false').to_s == 'true' &&
            ENV['FOREMAN_SECURITY_EVENTS_URL'].present?
        end

        def enqueue(payload)
          instance.enqueue(payload) if enabled?
        end
      end

      def initialize(
        url: ENV['FOREMAN_SECURITY_EVENTS_URL'],
        queue_size: ENV.fetch('FOREMAN_SECURITY_EVENTS_QUEUE', DEFAULT_QUEUE).to_i,
        connect_timeout: ENV.fetch('FOREMAN_SECURITY_EVENTS_CONNECT_TIMEOUT', DEFAULT_CONNECT_TIMEOUT).to_f,
        write_timeout: ENV.fetch('FOREMAN_SECURITY_EVENTS_WRITE_TIMEOUT', DEFAULT_WRITE_TIMEOUT).to_f
      )
        @url = url.to_s
        @queue = SizedQueue.new([queue_size, 1].max)
        @connect_timeout = connect_timeout
        @write_timeout = write_timeout
        @dropped = 0
        @sent = 0
        @failed = 0
        @mutex = Mutex.new
        @shutdown = false
        @worker = nil
        start_worker! if self.class.enabled?
      end

      def enqueue(payload)
        return false if @shutdown || !self.class.enabled?

        line = Payload.to_json_line(payload)
        @queue.push(line, true) # non_block
        true
      rescue ThreadError
        @mutex.synchronize { @dropped += 1 }
        false
      rescue StandardError
        false
      end

      def stats
        @mutex.synchronize do
          { sent: @sent, failed: @failed, dropped: @dropped, queued: @queue.size }
        end
      end

      def shutdown
        @shutdown = true
        begin
          @queue.push(nil, true)
        rescue ThreadError
          # queue full — worker will exit on next pop timeout path
        end
        @worker&.join(2)
      end

      private

      def start_worker!
        @worker = Thread.new do
          Thread.current.name = 'foreman-security-event-forwarder'
          Thread.current.abort_on_exception = false
          run_loop
        end
      end

      def run_loop
        uri = parse_uri(@url)
        until @shutdown
          line = @queue.pop
          break if line.nil?

          deliver(uri, line)
        end
      rescue StandardError => e
        Rails.logger.warn("SecurityEvent forwarder stopped: #{e.class}") if defined?(Rails)
      end

      def parse_uri(url)
        # Accept tcp://host:port or udp://host:port
        URI.parse(url)
      rescue URI::InvalidURIError
        nil
      end

      def deliver(uri, line)
        return fail_once unless uri && uri.host && uri.port

        case uri.scheme.to_s.downcase
        when 'tcp'
          deliver_tcp(uri.host, uri.port, line)
        when 'udp'
          deliver_udp(uri.host, uri.port, line)
        else
          fail_once
        end
      rescue StandardError
        fail_once
      end

      def deliver_tcp(host, port, line)
        sock = nil
        Timeout.timeout(@connect_timeout + @write_timeout) do
          sock = TCPSocket.new(host, port)
          sock.write(line.end_with?("\n") ? line : "#{line}\n")
          sock.flush
        end
        @mutex.synchronize { @sent += 1 }
      ensure
        sock&.close
      end

      def deliver_udp(host, port, line)
        sock = UDPSocket.new
        begin
          Timeout.timeout(@write_timeout) do
            sock.send(line.end_with?("\n") ? line : "#{line}\n", 0, host, port)
          end
          @mutex.synchronize { @sent += 1 }
        ensure
          sock.close
        end
      end

      def fail_once
        @mutex.synchronize { @failed += 1 }
        false
      end
    end
  end
end
