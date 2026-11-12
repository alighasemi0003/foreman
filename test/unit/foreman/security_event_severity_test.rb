# frozen_string_literal: true

require 'test_helper'

class Foreman::SecurityEventSeverityTest < ActiveSupport::TestCase
  test 'defines exactly six canonical severities' do
    assert_equal %w[ALERT CRITICAL ERROR WARNING NOTICE INFORMATIONAL],
                 Foreman::SecurityEvent::Severity.all
  end

  test 'each severity maps to syslog and a real Rails logger method' do
    Foreman::SecurityEvent::Severity.all.each do |sev|
      meta = Foreman::SecurityEvent::Severity.metadata(sev)
      assert_equal sev, meta[:severity]
      assert_includes 1..6, meta[:severity_syslog]
      assert Rails.logger.respond_to?(meta[:severity_rails].to_sym),
             "#{sev} must map to a Rails logger method"
    end
  end

  test 'unknown severity coerces safely without raising' do
    assert_equal 'INFORMATIONAL', Foreman::SecurityEvent::Severity.coerce('not-a-level')
    assert_nil Foreman::SecurityEvent::Severity.normalize('bogus')
  end

  test 'status and severity remain separate in payload' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'AUTHORIZATION_DENIED',
      status: 'DENIED',
      severity: 'WARNING'
    )
    assert_equal 'DENIED', payload['status']
    assert_equal 'WARNING', payload['severity']
    assert_equal 4, payload['severity_syslog']
    assert_equal 'warn', payload['severity_rails']
  end

  test 'payload includes severity for every required level' do
    Foreman::SecurityEvent::Severity.all.each do |sev|
      payload = Foreman::SecurityEvent::Payload.build(
        event: 'SYNTHETIC_F030',
        status: 'SUCCESS',
        severity: sev
      )
      assert_equal sev, payload['severity']
      assert_equal Foreman::SecurityEvent::Severity.to_syslog(sev), payload['severity_syslog']
    end
  end

  test 'legacy level warn resolves to WARNING when severity omitted' do
    sev = Foreman::SecurityEvent::Severity.resolve(event: 'CSRF_REJECTED', level: :warn)
    assert_equal 'WARNING', sev
  end

  test 'event defaults do not escalate auth failures to CRITICAL' do
    assert_equal 'WARNING', Foreman::SecurityEvent::Severity.default_for_event('ACCOUNT_LOCKOUT')
    assert_equal 'WARNING', Foreman::SecurityEvent::Severity.default_for_event('REAUTH_FAILED')
    assert_equal 'NOTICE', Foreman::SecurityEvent::Severity.default_for_event('REAUTH_SUCCESS')
    refute_equal 'CRITICAL', Foreman::SecurityEvent::Severity.default_for_event('AUTHORIZATION_DENIED')
  end

  test 'log emits NOTICE reauth success on info without secrets' do
    Rails.logger.expects(:info).with do |msg|
      msg.include?('REAUTH_SUCCESS') &&
        msg.include?('severity=NOTICE') &&
        msg.exclude?('SuperSecret') &&
        msg.exclude?('eyJhbGci')
    end
    payload = Foreman::SecurityEvent.log(
      event: 'REAUTH_SUCCESS',
      status: 'SUCCESS',
      actor: 'tester',
      details: 'password=SuperSecret token=eyJhbGciOiJIUzI1NiJ9.aaa.bbb'
    )
    assert_equal 'NOTICE', payload['severity']
    refute_match(/SuperSecret|eyJhbGci/, payload['details'].to_s)
    assert_match(/\[REDACTED\]/, payload['details'].to_s)
  end

  test 'log maps ALERT severity to fatal rails level' do
    Rails.logger.expects(:fatal).with(regexp_matches(/severity=ALERT/))
    payload = Foreman::SecurityEvent.log(
      event: 'SYNTHETIC_F030_ALERT',
      status: 'FAILURE',
      severity: :alert
    )
    assert_equal 'ALERT', payload['severity']
    assert_equal 'fatal', payload['severity_rails']
    assert_equal 1, payload['severity_syslog']
  end

  test 'unknown severity argument does not drop the event' do
    Rails.logger.expects(:info).at_least_once
    payload = Foreman::SecurityEvent.log(
      event: 'SYNTHETIC_UNKNOWN_SEV',
      status: 'SUCCESS',
      severity: 'purple'
    )
    assert_equal 'INFORMATIONAL', payload['severity']
  end

  test 'account lockout default severity remains WARNING compatible with F-043' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'ACCOUNT_LOCKOUT',
      status: 'LOCKED',
      level: :warn
    )
    assert_equal 'WARNING', payload['severity']
    assert_equal 'LOCKED', payload['status']
  end

  test 'rejection events keep DENIED status with WARNING severity' do
    payload = Foreman::SecurityEvent::Payload.build(
      event: 'CSRF_REJECTED',
      status: 'DENIED',
      level: :warn
    )
    assert_equal 'DENIED', payload['status']
    assert_equal 'WARNING', payload['severity']
  end
end
