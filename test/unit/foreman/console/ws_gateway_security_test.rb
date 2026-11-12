# frozen_string_literal: true

require 'test_helper'
require 'socket'
require 'timeout'
require 'json'
require 'foreman/console/ticket'
require 'foreman/console/ws_gateway'

class ForemanConsoleWsGatewaySecurityTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir('foreman-console-tickets-gw')
    ENV['FOREMAN_CONSOLE_TICKET_DIR'] = @dir
  end

  teardown do
    ENV.delete('FOREMAN_CONSOLE_TICKET_DIR')
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  def free_port
    s = TCPServer.new('127.0.0.1', 0)
    p = s.addr[1]
    s.close
    p
  end

  def start_gateway(ticket_id)
    port = free_port
    thread = Thread.new do
      Foreman::Console::WsGateway.new(
        port: port,
        ticket: ticket_id,
        store_dir: @dir,
        timeout: 15,
        idle_timeout: 5,
        bind: '127.0.0.1'
      ).serve
    rescue StandardError
      nil
    end
    sleep 0.15
    [port, thread]
  end

  def http_upgrade(sock, path)
    key = Base64.strict_encode64(SecureRandom.random_bytes(16))
    sock.write(
      "GET #{path} HTTP/1.1\r\n" \
      "Host: 127.0.0.1\r\n" \
      "Upgrade: websocket\r\n" \
      "Connection: Upgrade\r\n" \
      "Sec-WebSocket-Key: #{key}\r\n" \
      "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.readpartial(4096)
  end

  test 'rejects websocket without valid ticket' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 9,
      binding: 'host:A',
      ttl: 60
    )
    port, thread = start_gateway(ticket.id)
    begin
      sock = TCPSocket.new('127.0.0.1', port)
      resp = http_upgrade(sock, '/?ticket=wrong-ticket-value-should-fail')
      assert_match(%r{\AHTTP/1\.[01] 403}, resp)
      sock.close
    ensure
      thread.kill
    end
  end

  test 'rejects expired ticket' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 9,
      binding: 'host:A',
      ttl: -5
    )
    port, thread = start_gateway(ticket.id)
    begin
      sock = TCPSocket.new('127.0.0.1', port)
      resp = http_upgrade(sock, "/?ticket=#{ticket.id}")
      assert_match(%r{\AHTTP/1\.[01] 403}, resp)
      sock.close
    ensure
      thread.kill
    end
  end

  test 'host A ticket file is not valid_for host B binding' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 5901,
      binding: 'libvirt:host-a',
      ttl: 60
    )
    loaded = Foreman::Console::Ticket.load(ticket.id)
    assert loaded.valid_for?('libvirt:host-a')
    refute loaded.valid_for?('libvirt:host-b')
  end
end
