# frozen_string_literal: true

require 'test_helper'

class UsersControllerCaptchaTest < ActionController::TestCase
  tests UsersController

  setup do
    @prev_setting = Setting[:captcha_enabled]
    @prev_captcha = SETTINGS[:captcha]
    Setting[:captcha_enabled] = false
    SETTINGS[:captcha] = nil
    request.env['HTTPS'] = 'on'
  end

  teardown do
    Setting[:captcha_enabled] = @prev_setting
    SETTINGS[:captcha] = @prev_captcha
  end

  def enable_captcha_keys!
    SETTINGS[:captcha] = {
      provider: 'turnstile',
      turnstile: { site_key: 'public-site', secret_key: 'server-secret' },
    }
  end

  def login_params(login: users(:admin).login, password: 'secret', captcha: nil)
    params = { login: { login: login, password: password } }
    params[:login]['captcha_response'] = captcha unless captcha.nil?
    params
  end

  def captcha_flash_message
    flash[:inline] && flash[:inline][:error].to_s
  end

  test 'disabled captcha preserves normal login success' do
    Setting[:captcha_enabled] = false
    enable_captcha_keys!
    post :login, params: login_params
    assert_response :redirect
  end

  test 'login page props omit captcha when setting disabled' do
    Setting[:captcha_enabled] = false
    enable_captcha_keys!
    get :login
    assert_response :success
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)
    refute_includes response.body, 'server-secret'
  end

  test 'login page props include site key when setting enabled' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    get :login
    assert_response :success
    assert_match(/&quot;enabled&quot;:true/, response.body)
    assert_includes response.body, 'public-site'
    refute_includes response.body, 'server-secret'
    refute_match(/secret[_-]?key/i, response.body)
  end

  test 'setting toggle affects login props without restart' do
    enable_captcha_keys!
    Setting[:captcha_enabled] = false
    get :login
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)

    Setting[:captcha_enabled] = true
    get :login
    assert_match(/&quot;enabled&quot;:true/, response.body)
    assert_includes response.body, 'public-site'

    Setting[:captcha_enabled] = false
    get :login
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)
  end

  test 'enabled missing token is denied' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    post :login, params: login_params(captcha: '')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'enabled invalid captcha is denied' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    post :login, params: login_params(captcha: 'fake-token')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'enabled valid captcha with correct password logs in' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :success, message: 'captcha_ok')
    )
    post :login, params: login_params(captcha: 'good-token')
    assert_response :redirect
  end

  test 'enabled invalid captcha with correct password never verifies password' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    User.any_instance.expects(:matching_password?).never
    post :login, params: login_params(password: 'secret', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'CAPTCHA failure does not increment account lockout' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    user = users(:admin)
    before = user.failed_login_attempts.to_i
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    post :login, params: login_params(login: user.login, captcha: 'bad')
    user.reload
    assert_equal before, user.failed_login_attempts.to_i
  end

  test 'CAPTCHA failure message does not disclose account existence' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )

    post :login, params: login_params(login: users(:admin).login, captcha: 'bad')
    flash_existing = captcha_flash_message

    @request.reset_session
    post :login, params: login_params(login: 'no-such-user-xyz', captcha: 'bad')
    flash_missing = captcha_flash_message

    assert_match(/CAPTCHA verification failed/i, flash_existing)
    assert_match(/CAPTCHA verification failed/i, flash_missing)
    assert_equal flash_existing, flash_missing
  end

  test 'enabled valid captcha with wrong password follows normal failure path' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :success, message: 'captcha_ok')
    )
    post :login, params: login_params(password: 'wrong-password-xyz', captcha: 'good')
    assert_redirected_to login_users_path
    assert_match(/Incorrect username or password/i, captcha_flash_message)
  end

  test 'enabled missing keys fails closed without password check' do
    Setting[:captcha_enabled] = true
    SETTINGS[:captcha] = { provider: 'turnstile', turnstile: { site_key: '', secret_key: '' } }
    User.any_instance.expects(:matching_password?).never
    post :login, params: login_params(captcha: 'any')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'LDAP bind is not called when CAPTCHA fails' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    AuthSourceLdap.any_instance.expects(:authenticate).never
    post :login, params: login_params(login: 'ldap-user', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'reauthenticate endpoint does not require CAPTCHA' do
    Setting[:captcha_enabled] = true
    enable_captcha_keys!
    user = users(:admin)
    as_user user do
      post :reauthenticate, params: { login: { login: user.login, password: 'secret' } }
    end
    refute_match(/CAPTCHA/i, response.body)
    refute_match(/CAPTCHA/i, captcha_flash_message.to_s)
  end
end
