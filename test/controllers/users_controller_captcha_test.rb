# frozen_string_literal: true

require 'test_helper'

class UsersControllerCaptchaTest < ActionController::TestCase
  tests UsersController

  setup do
    @prev_setting = Setting[:captcha_enabled]
    Setting[:captcha_enabled] = false
    request.env['HTTPS'] = 'on'
  end

  teardown do
    Setting[:captcha_enabled] = @prev_setting
  end

  def seed_captcha!(answer:)
    session[Foreman::Captcha::Local::SESSION_KEY] = {
      'digest' => Foreman::Captcha::Local.digest(answer),
      'created_at' => Time.now.utc.to_i,
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
    post :login, params: login_params
    assert_response :redirect
  end

  test 'login page props omit captcha when setting disabled' do
    Setting[:captcha_enabled] = false
    get :login
    assert_response :success
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)
  end

  test 'login page props include local question when setting enabled' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(12, 34)
    get :login
    assert_response :success
    assert_match(/&quot;enabled&quot;:true/, response.body)
    assert_match(/&quot;provider&quot;:&quot;local&quot;/, response.body)
    assert_match(/What is/, response.body)
    refute_match(/&quot;answer&quot;/, response.body)
    refute_includes response.body, Foreman::Captcha::Local.digest('46')
  end

  test 'setting toggle affects login props without restart' do
    Setting[:captcha_enabled] = false
    get :login
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)

    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(2, 3)
    get :login
    assert_match(/&quot;enabled&quot;:true/, response.body)

    Setting[:captcha_enabled] = false
    get :login
    assert_match(/&quot;captcha&quot;:\{&quot;enabled&quot;:false\}/, response.body)
  end

  test 'enabled missing answer is denied' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(captcha: '')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'enabled wrong answer is denied' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(captcha: '99')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'enabled valid answer with correct password logs in' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(captcha: '42')
    assert_response :redirect
  end

  test 'enabled invalid captcha with correct password never verifies password' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    User.any_instance.expects(:matching_password?).never
    post :login, params: login_params(password: 'secret', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'CAPTCHA failure does not increment account lockout' do
    Setting[:captcha_enabled] = true
    user = users(:admin)
    before = user.failed_login_attempts.to_i
    seed_captcha!(answer: '42')
    post :login, params: login_params(login: user.login, captcha: 'bad')
    user.reload
    assert_equal before, user.failed_login_attempts.to_i
  end

  test 'CAPTCHA failure message does not disclose account existence' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(login: users(:admin).login, captcha: 'bad')
    flash_existing = captcha_flash_message

    seed_captcha!(answer: '42')
    post :login, params: login_params(login: 'no-such-user-xyz', captcha: 'bad')
    flash_missing = captcha_flash_message

    assert_match(/CAPTCHA verification failed/i, flash_existing)
    assert_match(/CAPTCHA verification failed/i, flash_missing)
    assert_equal flash_existing, flash_missing
  end

  test 'enabled valid captcha with wrong password follows normal failure path' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(password: 'wrong-password-xyz', captcha: '42')
    assert_redirected_to login_users_path
    assert_match(/Incorrect username or password/i, captcha_flash_message)
  end

  test 'expired challenge blocks login' do
    Setting[:captcha_enabled] = true
    session[Foreman::Captcha::Local::SESSION_KEY] = {
      'digest' => Foreman::Captcha::Local.digest('42'),
      'created_at' => 1.hour.ago.to_i,
    }
    User.any_instance.expects(:matching_password?).never
    post :login, params: login_params(captcha: '42')
    assert_redirected_to login_users_path
    assert_match(/CAPTCHA verification failed/i, captcha_flash_message)
  end

  test 'reused challenge blocks login' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    post :login, params: login_params(captcha: '42')
    assert_response :redirect

    # Replay same answer without a fresh challenge in session.
    reset_to_login = ActionController::TestRequest.create({})
    @request = reset_to_login if false # keep session from controller
    # Session was reset on successful login; captcha key gone.
    Setting[:captcha_enabled] = true
    User.current = nil
    session.delete(:user)
    session.delete(Foreman::Captcha::Local::SESSION_KEY)
    User.any_instance.expects(:matching_password?).never
    post :login, params: login_params(captcha: '42')
    assert_redirected_to login_users_path
  end

  test 'LDAP bind is not called when CAPTCHA fails' do
    Setting[:captcha_enabled] = true
    seed_captcha!(answer: '42')
    AuthSourceLdap.any_instance.expects(:authenticate).never
    post :login, params: login_params(login: 'ldap-user', captcha: 'bad')
    assert_redirected_to login_users_path
  end

  test 'reauthenticate endpoint does not require CAPTCHA' do
    Setting[:captcha_enabled] = true
    user = users(:admin)
    as_user user do
      post :reauthenticate, params: { login: { login: user.login, password: 'secret' } }
    end
    refute_match(/CAPTCHA/i, response.body)
    refute_match(/CAPTCHA/i, captcha_flash_message.to_s)
  end

  test 'captcha_challenge refresh returns new question when enabled' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(7, 8)
    get :captcha_challenge
    assert_response :success
    body = JSON.parse(response.body)
    assert_equal true, body['enabled']
    assert_equal 'local', body['provider']
    assert_match(/What is/, body['question'])
    refute body.key?('answer')
  end
end
