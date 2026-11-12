# frozen_string_literal: true

require 'test_helper'
require 'foreman/console/ticket'

class ForemanConsoleTicketTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir('foreman-console-tickets-test')
    ENV['FOREMAN_CONSOLE_TICKET_DIR'] = @dir
  end

  teardown do
    ENV.delete('FOREMAN_CONSOLE_TICKET_DIR')
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  test 'create stores password server-side and load validates id' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 5901,
      binding: 'host:1',
      ttl: 60
    )
    assert File.file?(ticket.path)
    assert_equal 0o600, File.stat(ticket.path).mode & 0o777

    loaded = Foreman::Console::Ticket.load(ticket.id)
    assert loaded.valid_for?('host:1')
    refute loaded.valid_for?('host:2')
    assert_equal 'synthVNC1', loaded.password
  end

  test 'consume is single-use and clears stored password' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 5901,
      binding: 'host:1',
      ttl: 60
    )
    pwd = ticket.consume!
    assert_equal 'synthVNC1', pwd
    assert ticket.used?
    data = JSON.parse(File.read(ticket.path))
    assert_equal true, data['used']
    assert_equal '', data['password']
    assert_raises { ticket.consume! }
  end

  test 'expired ticket is invalid' do
    ticket = Foreman::Console::Ticket.create!(
      password: 'synthVNC1',
      vnc_host: '127.0.0.1',
      vnc_port: 5901,
      binding: 'host:1',
      ttl: -1
    )
    assert ticket.expired?
    refute ticket.valid_for?('host:1')
  end

  test 'unknown ticket id returns nil' do
    assert_nil Foreman::Console::Ticket.load('not-a-real-ticket-id-value-000')
  end
end
