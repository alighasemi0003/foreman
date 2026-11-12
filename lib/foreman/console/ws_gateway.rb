# frozen_string_literal: true

require 'optparse'
require 'socket'
require 'openssl'
require 'timeout'
require 'uri'

begin
  require 'websocket/driver'
rescue LoadError
  # Bundler path may not be set when launched via absolute gem path; caller adds it.
end

module Foreman
  module Console
    # Browser WebSocket front-end for VNC consoles.
    # Validates a short-lived ticket, then bridges binary WS frames to an
    # RfbAuthProxy TCP session so the display password never reaches the browser.
    class WsGateway
      def self.run!(argv)
        options = {
          port: nil,
          ticket: nil,
          store_dir: nil,
          timeout: 120,
          idle_timeout: 120,
          ssl_cert: nil,
          ssl_key: nil,
          bind: '0.0.0.0',
        }
        OptionParser.new do |opts|
          opts.on('--port PORT', Integer) { |v| options[:port] = v }
          opts.on('--ticket TICKET', String) { |v| options[:ticket] = v }
          opts.on('--store-dir DIR', String) { |v| options[:store_dir] = v }
          opts.on('--timeout SEC', Integer) { |v| options[:timeout] = v }
          opts.on('--idle-timeout SEC', Integer) { |v| options[:idle_timeout] = v }
          opts.on('--ssl-cert PATH', String) { |v| options[:ssl_cert] = v }
          opts.on('--ssl-key PATH', String) { |v| options[:ssl_key] = v }
          opts.on('--bind ADDR', String) { |v| options[:bind] = v }
        end.parse!(argv)

        raise ArgumentError, '--port and --ticket are required' if options[:port].nil? || options[:ticket].to_s.empty?

        new(**options).serve
      end

      def initialize(port:, ticket:, store_dir: nil, timeout: 120, idle_timeout: 120,
                     ssl_cert: nil, ssl_key: nil, bind: '0.0.0.0')
        @port = Integer(port)
        @expected_ticket = ticket.to_s
        @store_dir = store_dir
        @timeout = Integer(timeout)
        @idle_timeout = Integer(idle_timeout)
        @ssl_cert = ssl_cert
        @ssl_key = ssl_key
        @bind = bind
      end

      def serve
        tcp = TCPServer.new(@bind, @port)
        server = wrap_ssl(tcp)
        deadline = Time.now + @timeout
        loop do
          raise Timeout::Error if Time.now >= deadline

          wait = [deadline - Time.now, 1].min
          readable, = IO.select([server], nil, nil, wait)
          next unless readable

          client = server.accept
          Thread.new { handle_client(client) }
        end
      ensure
        server&.close
        tcp&.close
      end

      private

      def wrap_ssl(tcp)
        return tcp if @ssl_cert.to_s.empty? || @ssl_key.to_s.empty?

        ctx = OpenSSL::SSL::SSLContext.new
        ctx.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
        ctx.key = OpenSSL::PKey.read(File.read(@ssl_key))
        OpenSSL::SSL::SSLServer.new(tcp, ctx)
      end

      def handle_client(client)
        conn = WsConnection.new(client)
        authorized = false
        password = nil
        vnc_host = nil
        vnc_port = nil

        conn.driver.on(:connect) do
          ticket_id = extract_ticket(conn.driver.url)
          unless Ticket.secure_compare(ticket_id.to_s, @expected_ticket)
            conn.reject_http(403, 'Forbidden')
            next
          end

          ticket = Ticket.load(@expected_ticket, store_dir: @store_dir)
          if ticket.nil? || ticket.expired? || ticket.used?
            conn.reject_http(403, 'Forbidden')
            next
          end

          password = ticket.consume!
          vnc_host = ticket.vnc_host
          vnc_port = ticket.vnc_port
          authorized = true
          conn.driver.start
        end

        conn.driver.on(:open) do
          next unless authorized

          begin
            run_rfb_bridge(conn, vnc_host, vnc_port, password)
          ensure
            password = nil
            conn.close
          end
        end

        conn.pump(idle_timeout: @idle_timeout)
      rescue StandardError
        # Never log credentials; swallow to keep the daemon alive.
      ensure
        client.close unless client.closed?
      end

      def extract_ticket(url)
        return '' if url.nil?

        uri = URI.parse(url)
        params = URI.decode_www_form(uri.query.to_s).to_h
        params['ticket'].to_s
      rescue URI::InvalidURIError
        ''
      end

      def run_rfb_bridge(conn, vnc_host, vnc_port, password)
        # Local RFB listener that performs hypervisor auth; WS side speaks RFB None.
        rfb_server = TCPServer.new('127.0.0.1', 0)
        rfb_port = rfb_server.addr[1]
        proxy_done = Queue.new

        acceptor = Thread.new do
          begin
            Timeout.timeout(10) do
              sock = rfb_server.accept
              RfbAuthProxy.new(vnc_host: vnc_host, vnc_port: vnc_port, password: password).handle(sock)
            ensure
              sock&.close
            end
          rescue StandardError
            nil
          ensure
            proxy_done << true
          end
        end

        rfb_client = TCPSocket.new('127.0.0.1', rfb_port)
        begin
          splice_ws_and_tcp(conn, rfb_client)
        ensure
          rfb_client.close unless rfb_client.closed?
          rfb_server.close unless rfb_server.closed?
          acceptor.join(2)
          proxy_done.pop unless proxy_done.empty?
        end
      end

      def splice_ws_and_tcp(conn, tcp)
        conn.driver.on(:message) do |event|
          data = event.data
          data = data.b if data.encoding != Encoding::ASCII_8BIT
          tcp.write(data) unless data.nil? || data.empty?
        end

        loop do
          rs, = IO.select([tcp, conn.socket], nil, nil, @idle_timeout)
          break if rs.nil?

          if rs.include?(conn.socket)
            begin
              data = conn.socket.read_nonblock(65_536)
            rescue IO::WaitReadable
              data = nil
            rescue EOFError
              break
            end
            break if data.nil? || data.empty?

            conn.driver.parse(data)
            break if conn.closed?
          end

          if rs.include?(tcp)
            begin
              data = tcp.read_nonblock(65_536)
            rescue IO::WaitReadable
              data = nil
            rescue EOFError
              break
            end
            break if data.nil? || data.empty?

            conn.driver.binary(data)
          end
        end
      end

      # Minimal WebSocket connection wrapper for websocket-driver.
      class WsConnection
        attr_reader :socket, :driver

        def initialize(socket)
          @socket = socket
          @driver = WebSocket::Driver.server(self)
          @closed = false
          @http_rejected = false
        end

        def write(data)
          @socket.write(data)
        end

        def closed?
          @closed
        end

        def close
          return if @closed

          @closed = true
          @driver.close rescue nil
          @socket.close unless @socket.closed?
        end

        def reject_http(status, message)
          return if @http_rejected

          @http_rejected = true
          body = message.to_s
          @socket.write(
            "HTTP/1.1 #{status} #{message}\r\n" \
            "Content-Type: text/plain\r\n" \
            "Content-Length: #{body.bytesize}\r\n" \
            "Connection: close\r\n\r\n#{body}"
          )
          close
        end

        def pump(idle_timeout:)
          loop do
            break if @closed

            rs, = IO.select([@socket], nil, nil, idle_timeout)
            break if rs.nil?

            begin
              data = @socket.read_nonblock(65_536)
            rescue IO::WaitReadable
              next
            rescue EOFError
              break
            end
            break if data.nil? || data.empty?

            @driver.parse(data)
            break if @closed || @http_rejected
          end
        end
      end
    end
  end
end
