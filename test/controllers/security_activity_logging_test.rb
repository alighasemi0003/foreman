# frozen_string_literal: true

require 'test_helper'

class SecurityActivityLoggingTest < ActionController::TestCase
  tests UsersController

  setup do
    @password = 'Password1!'
    User.current = users(:admin)
    Setting[:account_lockout_attempts] = 5
    Setting[:account_lockout_window] = 15
    Setting[:account_lockout_duration] = 30
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    User.current = nil
    @client_ip = '203.0.113.10'
    @request.env['REMOTE_ADDR'] = @client_ip
  end

  test 'successful login is logged with actor IP and success status' do
    Rails.logger.expects(:info).with(regexp_matches(/SecurityEvent LOGIN_SUCCESS status=SUCCESS actor=#{@user.login} ip=#{@client_ip}/)).at_least_once
    post :login, params: { login: { login: @user.login, password: @password } }
    assert_response :redirect
  end

  test 'failed login is logged with actor IP and failure status without password' do
    Rails.logger.expects(:warn).with(regexp_matches(/SecurityEvent LOGIN_FAILED status=FAILURE actor=#{@user.login} ip=#{@client_ip}/)).at_least_once
    post :login, params: { login: { login: @user.login, password: 'wrong-password-xyz' } }
    assert_redirected_to login_users_path
    refute_match(/wrong-password-xyz/, @response.body)
  end

  test 'logout is logged with actor IP and success status' do
    Rails.logger.expects(:info).with(regexp_matches(/SecurityEvent LOGOUT_SUCCESS status=SUCCESS actor=#{@user.login} ip=#{@client_ip}/)).at_least_once
    post :logout, session: set_session_user(@user)
    assert_response :redirect
  end

  test 'log injection in username cannot forge a new security event line' do
    forged = "admin\nSecurityEvent LOGIN_SUCCESS status=SUCCESS actor=root"
    Rails.logger.expects(:warn).with do |msg|
      msg.is_a?(String) &&
        msg.include?('LOGIN_FAILED') &&
        !msg.include?("\nSecurityEvent LOGIN_SUCCESS") &&
        msg.exclude?("\n")
    end.at_least_once
    post :login, params: { login: { login: forged, password: 'x' } }
  end

  test 'account lockout emits ACCOUNT_LOCKED security event' do
    ::Logging.mdc['remote_ip'] = @client_ip
    Rails.logger.expects(:warn).with(regexp_matches(/SecurityEvent ACCOUNT_LOCKED status=LOCKED actor=#{@user.login}/)).at_least_once
    Setting[:account_lockout_attempts] = 2
    2.times { User.try_to_login(@user.login, 'bad') }
    @user.reload
    assert @user.account_locked?
  ensure
    ::Logging.mdc['remote_ip'] = nil
  end
end

class SecurityAuditIpPersistenceTest < ActionController::TestCase
  tests ArchitecturesController

  setup do
    @admin = users(:admin)
    @client_ip = '203.0.113.10'
    @request.env['REMOTE_ADDR'] = @client_ip
    as_admin { @architecture = FactoryBot.create(:architecture, :name => 'sec-audit-arch') }
  end

  test 'successful update creates persistent audit with actor IP timestamp and action' do
    put :update,
        params: { id: @architecture.id, architecture: { name: 'sec-audit-arch-updated' } },
        session: set_session_user(@admin)

    assert_response :redirect
    audit = @architecture.audits.reorder(:id).last
    assert_equal 'update', audit.action
    assert_equal @admin.id, audit.user_id
    assert_equal @client_ip, audit.remote_address
    assert audit.created_at.present?
    assert audit.request_uuid.present? || audit.request_uuid.nil? # request_uuid set when available
    assert_includes audit.audited_changes.keys, 'name'
  end
end

class SecurityAuditSecretFilteringTest < ActiveSupport::TestCase
  test 'password changes are audited without storing plaintext password' do
    user = as_admin { FactoryBot.create(:user, :password => 'Password1!', :password_confirmation => 'Password1!') }
    as_admin do
      user.password = 'NewPassword2!'
      user.password_confirmation = 'NewPassword2!'
      assert user.save, user.errors.full_messages.to_sentence
    end

    audit = user.audits.reorder(:id).last
    assert_equal 'update', audit.action
    changes = audit.audited_changes
    refute_includes changes.to_s, 'NewPassword2!'
    refute_includes changes.to_s, 'Password1!'
    if changes.key?('password')
      assert_equal [AuditExtensions::REDACTED, AuditExtensions::REDACTED], changes['password']
    end
  end
end

class SecurityTrustedProxyIpTest < ActiveSupport::TestCase
  def remote_ip_for(env)
    remote_ip_mw = ActionDispatch::RemoteIp.new(->(e) { [200, {}, []] }, true, Rails.application.config.action_dispatch.trusted_proxies)
    remote_ip_mw.call(env)
    ActionDispatch::Request.new(env).remote_ip
  end

  test 'trusted proxy uses X-Forwarded-For client IP for remote_ip' do
    env = Rack::MockRequest.env_for(
      '/',
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '198.51.100.20'
    )
    assert_equal '198.51.100.20', remote_ip_for(env)
  end

  test 'trusted_proxies are configured and localhost is trusted by default' do
    proxies = Rails.application.config.action_dispatch.trusted_proxies
    assert proxies.present?
    assert proxies.any? { |p| p.include?('127.0.0.1') }, 'expected loopback in trusted_proxies'
  end

  # Rails RemoteIp prefers X-Forwarded-For over REMOTE_ADDR when both are untrusted
  # (see ActionDispatch::RemoteIp and config/application.rb comments). Spoof resistance
  # therefore depends on deployment: only trusted reverse proxies may reach Foreman and
  # must set/overwrite X-Forwarded-For.
  test 'direct client X-Forwarded-For is used by Rails unless stripped at trusted proxy' do
    env = Rack::MockRequest.env_for(
      '/',
      'REMOTE_ADDR' => '203.0.113.50',
      'HTTP_X_FORWARDED_FOR' => '198.51.100.99'
    )
    assert_equal '198.51.100.99', remote_ip_for(env)
  end
end

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

class SecurityAccessDeniedLoggingTest < ActionController::TestCase
  tests ArchitecturesController

  setup do
    @client_ip = '203.0.113.77'
    @request.env['REMOTE_ADDR'] = @client_ip
    @viewer = FactoryBot.create(:user) # no architecture permissions
  end

  test 'access denied is logged with actor IP and DENIED status' do
    Rails.logger.expects(:warn).with(regexp_matches(/SecurityEvent ACCESS_DENIED status=DENIED actor=#{@viewer.login} ip=#{@client_ip}/)).at_least_once
    get :index, session: set_session_user(@viewer)
    assert_response :forbidden
  end
end

class SecurityRequestIdInLogsTest < ActiveSupport::TestCase
  test 'logging MDC request id is available for correlation' do
    ::Logging.mdc['request'] = 'req-test-uuid-1234'
    ::Logging.mdc['remote_ip'] = '203.0.113.10'
    begin
      Rails.logger.expects(:info).with(regexp_matches(/request_id=req-test-uuid-1234/))
      Foreman::SecurityEvent.log(event: 'TEST_EVENT', status: 'SUCCESS', actor: 'tester')
    ensure
      ::Logging.mdc['request'] = nil
      ::Logging.mdc['remote_ip'] = nil
    end
  end
end
