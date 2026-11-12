# frozen_string_literal: true

require 'test_helper'
require 'socket'
require 'json'

class SecurityEventPayloadTest < ActiveSupport::TestCase
  test 'payload schema includes required fields and UTC timestamp' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'REAUTH_SUCCESS',
      status: 'SUCCESS',
      actor: 'admin',
      actor_id: 1,
      ip: '203.0.113.10',
      request_id: 'req-1',
      operation: 'users.set_admin',
      details: 'ok'
    )
    assert_equal 'security', payload['event_type']
    assert_equal 'REAUTH_SUCCESS', payload['event_id']
    assert_equal 'SUCCESS', payload['status']
    assert_equal 'admin', payload['actor']
    assert_equal 1, payload['actor_id']
    assert_equal '203.0.113.10', payload['client_ip']
    assert_equal 'req-1', payload['request_id']
    assert_equal 'foreman', payload['source_service']
    assert_match(/\d{4}-\d{2}-\d{2}T/, payload['ts'])
    assert payload['ts'].end_with?('Z') || payload['ts'].include?('+00:00') || payload['ts'].include?('Z')
  end

  test 'scrub_details redacts password and jwt-like tokens' do
    dirty = 'password=SuperSecretPass1! token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb bearer=nope'
    clean = Foreman::SecurityEvent::Payload.scrub_details(dirty)
    refute_includes clean, 'SuperSecretPass1!'
    assert_includes clean, '[REDACTED]'
    refute_match(/eyJhbGciOi/, clean)
  end
end

class SecurityEventForwarderTest < ActiveSupport::TestCase
  setup do
    Foreman::SecurityEvent::Forwarder.reset!
    ENV['FOREMAN_SECURITY_EVENTS_ENABLED'] = 'true'
  end

  teardown do
    Foreman::SecurityEvent::Forwarder.reset!
    ENV.delete('FOREMAN_SECURITY_EVENTS_ENABLED')
    ENV.delete('FOREMAN_SECURITY_EVENTS_URL')
  end

  test 'tcp forwarder delivers json line to local receiver' do
    received = Queue.new
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thr = Thread.new do
      client = server.accept
      line = client.gets
      received << line
      client.close
    end

    ENV['FOREMAN_SECURITY_EVENTS_URL'] = "tcp://127.0.0.1:#{port}"
    Foreman::SecurityEvent::Forwarder.reset!
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'HTTP_RATE_LIMIT_EXCEEDED',
      status: 'DENIED',
      actor: 'anon',
      ip: '198.51.100.7',
      request_id: 'corr-42'
    )
    assert Foreman::SecurityEvent::Forwarder.enqueue(payload)

    line = received.pop
    thr.join(2)
    server.close

    obj = JSON.parse(line)
    assert_equal 'HTTP_RATE_LIMIT_EXCEEDED', obj['event_id']
    assert_equal 'DENIED', obj['status']
    assert_equal 'corr-42', obj['request_id']
    assert_equal '198.51.100.7', obj['client_ip']
  end

  test 'collector outage does not raise from SecurityEvent.log' do
    ENV['FOREMAN_SECURITY_EVENTS_URL'] = 'tcp://127.0.0.1:1'
    Foreman::SecurityEvent::Forwarder.reset!
    assert_nothing_raised do
      Foreman::SecurityEvent.log(event: 'REAUTH_FAILED', status: 'FAILURE', actor: 'x')
    end
  end

  test 'full queue drops without raising' do
    ENV['FOREMAN_SECURITY_EVENTS_URL'] = 'tcp://127.0.0.1:1'
    ENV['FOREMAN_SECURITY_EVENTS_QUEUE'] = '1'
    Foreman::SecurityEvent::Forwarder.reset!
    fwd = Foreman::SecurityEvent::Forwarder.instance
    # Fill queue; further enqueues should return false, not raise
    payload = Foreman::SecurityEvent::Payload.build(event: 'X', status: 'SUCCESS')
    fwd.enqueue(payload)
    # Depending on worker drain timing, second may succeed or drop — must not raise
    assert_nothing_raised { 5.times { fwd.enqueue(payload) } }
  ensure
    ENV.delete('FOREMAN_SECURITY_EVENTS_QUEUE')
  end
end
