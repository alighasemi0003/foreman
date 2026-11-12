# frozen_string_literal: true

require 'socket'

module Foreman
  module Console
    # TCP RFB proxy that authenticates to the hypervisor VNC server using a
    # server-held password, then offers security type None to the browser-facing
    # side so noVNC never receives the display password.
    class RfbAuthProxy
      class Error < StandardError; end

      RFB_VERSION = "RFB 003.008\n"
      SEC_NONE = 1
      SEC_VNC = 2

      def initialize(vnc_host:, vnc_port:, password:)
        @vnc_host = vnc_host
        @vnc_port = Integer(vnc_port)
        @password = password.to_s
      end

      # client_io speaks RFB (already WebSocket-decoded by the gateway).
      def handle(client_io)
        server_io = TCPSocket.new(@vnc_host, @vnc_port)
        begin
          authenticate_to_server(server_io)
          offer_none_to_client(client_io)
          forward_client_init(client_io, server_io)
          forward_server_init(server_io, client_io)
          splice(client_io, server_io)
        ensure
          server_io.close unless server_io.closed?
        end
      end

      private

      def authenticate_to_server(server_io)
        read_exact(server_io, 12)
        write_all(server_io, RFB_VERSION)

        count = read_exact(server_io, 1).unpack1('C')
        types = read_exact(server_io, count).bytes
        if types.include?(SEC_VNC)
          write_all(server_io, [SEC_VNC].pack('C'))
          challenge = read_exact(server_io, 16)
          write_all(server_io, VncDes.encrypt(@password, challenge))
        elsif types.include?(SEC_NONE)
          write_all(server_io, [SEC_NONE].pack('C'))
        else
          raise Error, 'VNC server offered no supported security types'
        end

        result = read_exact(server_io, 4).unpack1('N')
        raise Error, 'VNC authentication to hypervisor failed' unless result.zero?
      end

      def offer_none_to_client(client_io)
        write_all(client_io, RFB_VERSION)
        read_exact(client_io, 12)
        write_all(client_io, [1, SEC_NONE].pack('CC'))
        selected = read_exact(client_io, 1).unpack1('C')
        raise Error, 'Client refused VNC security type None' unless selected == SEC_NONE

        write_all(client_io, [0].pack('N'))
      end

      def forward_client_init(client_io, server_io)
        write_all(server_io, read_exact(client_io, 1))
      end

      def forward_server_init(server_io, client_io)
        header = read_exact(server_io, 24)
        name_len = header[-4, 4].unpack1('N')
        name = read_exact(server_io, name_len)
        write_all(client_io, header + name)
      end

      def splice(a, b)
        loop do
          rs, = IO.select([a, b], nil, nil, 30)
          break if rs.nil?

          rs.each do |sock|
            other = (sock == a) ? b : a
            data = sock.recv_nonblock(65_536, exception: false)
            next if data == :wait_readable
            return if data.nil? || data.empty?

            write_all(other, data)
          end
        end
      end

      def read_exact(io, n)
        buf = +''.b
        while buf.bytesize < n
          chunk = io.read(n - buf.bytesize)
          raise EOFError, 'RFB connection closed' if chunk.nil? || chunk.empty?

          buf << chunk
        end
        buf
      end

      def write_all(io, data)
        data = data.b
        until data.empty?
          written = io.write(data)
          data = data.byteslice(written..)
        end
      end
    end
  end
end
