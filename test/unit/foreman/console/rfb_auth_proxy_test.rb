# frozen_string_literal: true

require 'test_helper'
require 'socket'
require 'timeout'
require 'foreman/console/rfb_auth_proxy'
require 'foreman/console/vnc_des'

class ForemanConsoleRfbAuthProxyTest < ActiveSupport::TestCase
  def start_fake_vnc(password)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      sock = server.accept
      begin
        sock.write("RFB 003.008\n")
        ver = sock.read(12)
        raise 'bad ver' unless ver&.start_with?('RFB')

        sock.write([1, 2].pack('CC')) # one type: VNC auth
        selected = sock.read(1).unpack1('C')
        raise 'expected VNC auth' unless selected == 2

        challenge = SecureRandom.random_bytes(16)
        sock.write(challenge)
        response = sock.read(16)
        expected = Foreman::Console::VncDes.encrypt(password, challenge)
        sock.write(response == expected ? [0].pack('N') : [1].pack('N'))
        # ClientInit
        sock.read(1)
        # ServerInit: 100x40, pixel format zeros, name "t"
        name = 't'
        sock.write([100, 40].pack('nn') + ("\0" * 16) + [name.bytesize].pack('N') + name)
        # keep open briefly for splice
        sleep 0.2
      ensure
        sock&.close
        server.close
      end
    end
    [port, thread]
  end

  def speak_none_client(io)
    ver = io.read(12)
    assert ver.start_with?('RFB')
    io.write("RFB 003.008\n")
    types = io.read(2)
    assert_equal [1, 1], types.unpack('CC')
    io.write([1].pack('C'))
    assert_equal 0, io.read(4).unpack1('N')
    io.write([1].pack('C')) # ClientInit shared
    header = io.read(24)
    name_len = header[-4, 4].unpack1('N')
    name = io.read(name_len)
    assert_equal 't', name
  end

  test 'authenticates to VNC server and offers None to client' do
    password = 'synthPW01'
    port, thread = start_fake_vnc(password)
    begin
      # Pair of connected sockets: proxy sees "client", test speaks as noVNC
      ss = TCPServer.new('127.0.0.1', 0)
      client_to_proxy = nil
      proxy_client = nil
      acceptor = Thread.new { proxy_client = ss.accept }
      client_to_proxy = TCPSocket.new('127.0.0.1', ss.addr[1])
      acceptor.join(1)
      ss.close

      proxy_thread = Thread.new do
        Foreman::Console::RfbAuthProxy.new(
          vnc_host: '127.0.0.1',
          vnc_port: port,
          password: password
        ).handle(proxy_client)
      end

      Timeout.timeout(5) { speak_none_client(client_to_proxy) }
      client_to_proxy.close
      proxy_thread.join(2)
      thread.join(2)
    end
  end
end
