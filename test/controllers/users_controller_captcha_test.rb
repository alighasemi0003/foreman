# frozen_string_literal: true

require 'test_helper'

class UsersControllerCaptchaTest < ActionController::TestCase
  tests UsersController

  setup do
    @prev_captcha = SETTINGS[:captcha]
    User.current = nil
    @request.session.delete(:user)
  end

  teardown do
    SETTINGS[:captcha] = @prev_captcha
  end

  def enable_captcha!
    SETTINGS[:captcha] = {
      enabled: true,
      provider: 'turnstile',
      turnstile: { site_key: 'public-site', secret_key: 'server-secret' },
    }
  end

  def disable_captcha!
    SETTINGS[:captcha] = { enabled: false }
  end

  def login_params(login: users(:admin).login, password: 'secret', captcha: nil)
    params = { login: { 'login' => login, 'password' => password } }
    params[:login]['captcha_response'] = captcha unless captcha.nil?
    params
  end

  def captcha_flash_message
    inline = flash[:inline]
    if inline.is_a?(Hash)
      (inline[:error] || inline['error']).to_s
    else
      flash[:error].to_s
    end
  end

  test 'disabled captcha preserves normal login success' do
    disable_captcha!
    Foreman::Captcha.expects(:verify).never
    post :login, params: login_params
    assert_response :redirect
    assert_equal users(:admin).id, session[:user]
  end

  test 'enabled missing token denies and does not call try_to_login' do
    enable_captcha!
    User.expects(:try_to_login).never
    post :login, params: login_params(captcha: '')
    assert_redirected_to login_users_path
    assert_nil session[:user]
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'enabled invalid token denies without password verification' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    User.expects(:try_to_login).never
    AuthSourceInternal.any_instance.expects(:authenticate).never

    post :login, params: login_params(captcha: 'fake-token')
    assert_redirected_to login_users_path
    assert_nil session[:user]
  end

  test 'enabled valid captcha with correct password logs in' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :success, message: 'captcha_ok')
    )
    post :login, params: login_params(captcha: 'good-token')
    assert_response :redirect
    assert_equal users(:admin).id, session[:user]
  end

  test 'enabled invalid captcha with correct password never verifies password' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    User.any_instance.expects(:matching_password?).never
    AuthSourceInternal.any_instance.expects(:authenticate).never
    post :login, params: login_params(password: 'secret', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'CAPTCHA failure does not increment account lockout' do
    enable_captcha!
    user = users(:admin)
    user.update_columns(failed_login_attempts: 0, failed_login_started_at: nil, locked_until: nil)
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    post :login, params: login_params(login: user.login, captcha: 'bad')
    user.reload
    assert_equal 0, user.failed_login_attempts
  end

  test 'CAPTCHA failure message does not disclose account existence' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )

    post :login, params: login_params(login: users(:admin).login, captcha: 'bad')
    flash_existing = captcha_flash_message

    @request.session.clear
    User.current = nil
    post :login, params: login_params(login: 'no-such-user-xyz', captcha: 'bad')
    flash_missing = captcha_flash_message

    assert_match(/CAPTCHA verification failed/i, flash_existing)
    assert_match(/CAPTCHA verification failed/i, flash_missing)
    refute_match(/incorrect username or password/i, flash_existing)
    refute_match(/incorrect username or password/i, flash_missing)
  end

  test 'enabled valid captcha with wrong password follows normal failure path' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :success, message: 'captcha_ok')
    )
    post :login, params: login_params(password: 'wrong-password-xyz', captcha: 'good')
    assert_redirected_to login_users_path
    assert_nil session[:user]
  end

  test 'login page never exposes secret key' do
    enable_captcha!
    get :login
    assert_response :success
    body = @response.body
    refute_match(/server-secret/, body)
    refute_match(/secretKey|secret_key|TURNSTILE_SECRET/i, body)
    assert_match(/public-site/, body)
  end

  test 'LDAP bind is not called when CAPTCHA fails' do
    enable_captcha!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    AuthSourceLdap.any_instance.expects(:authenticate).never
    post :login, params: login_params(login: 'ldap-user', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'reauthenticate endpoint does not require CAPTCHA' do
    enable_captcha!
    Foreman::Captcha.expects(:verify).never
    @request.session[:user] = users(:admin).id
    @request.session[:expires_at] = 5.minutes.from_now
    post :reauthenticate, params: { password: 'secret' }, as: :json
    # May succeed or fail auth, but must not be CAPTCHA-gated
    refute_equal login_users_path, response.redirect_url.to_s
    refute_match(/CAPTCHA/i, response.body)
  end
end
