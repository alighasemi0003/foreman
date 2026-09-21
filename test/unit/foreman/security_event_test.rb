# frozen_string_literal: true

require 'test_helper'

class SecurityEventSanitizeTest < ActiveSupport::TestCase
  test 'sanitize strips control characters used for log forging' do
    dirty = "admin\r\nLOGIN_SUCCESS\tstatus=SUCCESS"
    clean = Foreman::SecurityEvent.sanitize(dirty)
    refute_includes clean, "\n"
    refute_includes clean, "\r"
    refute_includes clean, "\t"
    assert_includes clean, 'admin'
  end

  test 'filter_parameters still covers auth secrets' do
    filters = Rails.application.config.filter_parameters.map(&:to_s)
    %w[password token api_key authorization secret].each do |key|
      assert filters.any? { |f| f.include?(key) }, "expected #{key} filtered"
    end
  end
end

class SecurityEventRequestContextTest < ActiveSupport::TestCase
  test 'logging MDC request id and IP are available for correlation' do
    ::Logging.mdc['request'] = 'req-test-uuid-1234'
    ::Logging.mdc['remote_ip'] = '203.0.113.10'
    begin
      Rails.logger.expects(:info).with(regexp_matches(/request_id=req-test-uuid-1234/))
      Foreman::SecurityEvent.log(event: 'REAUTH_SUCCESS', status: 'SUCCESS', actor: 'tester')
    ensure
      ::Logging.mdc['request'] = nil
      ::Logging.mdc['remote_ip'] = nil
    end
  end

  test 'reauth event types can be emitted without password leakage' do
    ::Logging.mdc['remote_ip'] = '203.0.113.44'
    begin
      %w[REAUTH_SUCCESS REAUTH_FAILED REAUTH_UNSUPPORTED REAUTH_REQUIRED].each do |event|
        status = event == 'REAUTH_SUCCESS' ? 'SUCCESS' : 'FAILURE'
        Rails.logger.expects(:info).with do |msg|
          msg.is_a?(String) &&
            msg.include?("SecurityEvent #{event}") &&
            msg.exclude?('SuperSecretPass1!') &&
            msg.exclude?('Bearer ') &&
            msg.exclude?('password=')
        end
        Foreman::SecurityEvent.log(
          event: event,
          status: status,
          actor: 'admin',
          details: 'action=users.set_admin'
        )
      end
    ensure
      ::Logging.mdc['remote_ip'] = nil
    end
  end

  test 'sanitize truncates extremely long actor values' do
    long = 'a' * 500
    clean = Foreman::SecurityEvent.sanitize(long)
    assert_operator clean.length, :<=, 200
  end

  test 'current_ip and current_request_id read Logging MDC' do
    ::Logging.mdc['remote_ip'] = '198.51.100.9'
    ::Logging.mdc['request'] = 'uuid-abc'
    begin
      assert_equal '198.51.100.9', Foreman::SecurityEvent.current_ip
      assert_equal 'uuid-abc', Foreman::SecurityEvent.current_request_id
    ensure
      ::Logging.mdc['remote_ip'] = nil
      ::Logging.mdc['request'] = nil
    end
  end
end

class SecurityEventDoesNotDuplicateLoginAuditTest < ActiveSupport::TestCase
  test 'SecurityEvent module is available without replacing Audit login events' do
    assert defined?(Foreman::SecurityEvent)
    # Upstream Foreman 5.0 login/logout/failed_login Audits remain the interactive
    # login audit path; SecurityEvent is complementary telemetry (esp. REAUTH_*).
    source = File.read(Rails.root.join('app/controllers/users_controller.rb'))
    assert_match(/log_authentication_event|Audit\.manual_event!/, source)
    refute_match(/SecurityEvent\.log\(\s*event:\s*['\"]LOGIN_/, source)
  end
end
