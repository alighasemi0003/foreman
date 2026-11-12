# frozen_string_literal: true

require 'test_helper'

class Foreman::SecurityEventTaxonomyTest < ActiveSupport::TestCase
  test 'known events receive category severity and classification' do
    {
      'ACCOUNT_LOCKOUT' => %w[account_password WARNING internal],
      'CSRF_REJECTED' => %w[security_control_rejection WARNING internal],
      'AUTHORIZATION_DENIED' => %w[authorization WARNING internal],
      'REAUTH_SUCCESS' => %w[authentication NOTICE internal],
      'REAUTH_FAILED' => %w[authentication WARNING internal],
      'HTTP_RATE_LIMIT_EXCEEDED' => %w[availability WARNING internal],
      'JWT_INVALIDATE' => %w[crypto_secret NOTICE confidential],
      'HOST_INFO_EXPORT' => %w[data_access NOTICE confidential],
    }.each do |event_id, (cat, sev, klass)|
      policy = Foreman::SecurityEvent::Taxonomy.lookup(event_id)
      assert_equal cat, policy[:category], event_id
      assert_equal sev, policy[:severity], event_id
      assert_equal klass, policy[:classification], event_id
      assert policy[:known]
    end
  end

  test 'payload applies taxonomy fields and keeps status independent' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'AUTHORIZATION_DENIED',
      status: 'DENIED',
      level: :warn
    )
    assert_equal 'DENIED', payload['status']
    assert_equal 'WARNING', payload['severity']
    assert_equal 'authorization', payload['event_category']
    assert_equal 'internal', payload['data_classification']
    assert_equal Foreman::SecurityEvent::Taxonomy.policy_id, payload['taxonomy_policy']
    assert_equal 180, payload['retention_days']
  end

  test 'unknown event uses safe fallback and is not dropped' do
    policy = Foreman::SecurityEvent::Taxonomy.lookup('TOTALLY_UNKNOWN_EVENT')
    refute policy[:known]
    assert_equal 'unknown', policy[:category]
    assert_equal 'INFORMATIONAL', policy[:severity]
    assert_equal 'internal', policy[:classification]

    Rails.logger.stubs(:info)
    payload = Foreman::SecurityEvent.log(
      event: 'TOTALLY_UNKNOWN_EVENT',
      status: 'SUCCESS',
      actor: 'f031'
    )
    assert_equal 'unknown', payload['event_category']
    assert_equal 'INFORMATIONAL', payload['severity']
    assert_equal 'internal', payload['data_classification']
  end

  test 'F-043 lockout follows taxonomy policy' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'ACCOUNT_LOCKOUT',
      status: 'LOCKED',
      target: 'victim',
      reason_code: 'failed_password_threshold',
      level: :warn
    )
    assert_equal 'LOCKED', payload['status']
    assert_equal 'WARNING', payload['severity']
    assert_equal 'account_password', payload['event_category']
    assert_equal 'internal', payload['data_classification']
  end

  test 'F-044 rejection events follow taxonomy policy' do
    %w[CSRF_REJECTED AUTHORIZATION_DENIED SECURITY_CONTROL_REJECTED].each do |event|
      payload = Foreman::SecurityEvent::Payload.build(event: event, status: 'DENIED', level: :warn)
      assert_equal 'DENIED', payload['status']
      assert_equal 'WARNING', payload['severity']
      assert_includes %w[security_control_rejection authorization], payload['event_category']
    end
  end

  test 'secrets are redacted regardless of classification' do
    %w[internal confidential restricted].each do |klass|
      payload = Foreman::SecurityEvent::Payload.build(
        event: 'JWT_INVALIDATE',
        status: 'SUCCESS',
        classification: klass,
        details: 'password=Secret1! token=eyJhbGciOiJIUzI1NiJ9.aaa.bbb cookie=abc session_id=deadbeef private_key=PEM'
      )
      text = payload['details'].to_s
      refute_match(/Secret1!/, text)
      refute_match(/eyJhbGci/, text)
      refute_match(/deadbeef/, text)
      refute_match(/PEM/, text)
      assert_match(/\[REDACTED/, text)
      assert_equal Foreman::SecurityEvent::Taxonomy.normalize_classification(klass),
                   payload['data_classification']
    end
  end

  test 'actor target ip request_id remain available' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'REAUTH_SUCCESS',
      status: 'SUCCESS',
      actor: 'alice',
      actor_id: 42,
      target: 'users#update',
      ip: '203.0.113.9',
      request_id: 'req-f031'
    )
    assert_equal 'alice', payload['actor']
    assert_equal 42, payload['actor_id']
    assert_equal 'users#update', payload['target']
    assert_equal '203.0.113.9', payload['client_ip']
    assert_equal 'req-f031', payload['request_id']
  end

  test 'collector integrity event is critical severity with internal classification' do
    policy = Foreman::SecurityEvent::Taxonomy.lookup('COLLECTOR_INTEGRITY_FAILURE')
    assert_equal 'CRITICAL', policy[:severity]
    assert_equal 'internal', policy[:classification]
    assert_equal 'audit_integrity', policy[:category]
  end

  test 'severity defaults come from taxonomy for known events' do
    assert_equal 'WARNING', Foreman::SecurityEvent::Severity.default_for_event('ACCOUNT_LOCKOUT')
    assert_equal 'NOTICE', Foreman::SecurityEvent::Severity.default_for_event('JWT_INVALIDATE')
  end

  test 'classification override cannot bypass normalize' do
    assert_equal 'internal',
                 Foreman::SecurityEvent::Taxonomy.resolve_classification(
                   event: 'REAUTH_SUCCESS', classification: 'not-real'
                 )
  end

  test 'catalog enumerates known events without dropping policy id' do
    catalog = Foreman::SecurityEvent::Taxonomy.catalog
    assert_operator catalog.size, :>=, 10
    assert catalog.all? { |e| e[:taxonomy_policy] == Foreman::SecurityEvent::Taxonomy.policy_id }
  end
end
