# frozen_string_literal: true

require 'test_helper'

class UsersControllerFailedLoginNoticeTest < ActionController::TestCase
  tests UsersController

  setup do
    UserLoginEvent.delete_all
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    Setting[:authorize_login_delegation] = false
    Setting[:captcha_enabled] = false
    Setting[:account_lockout_attempts] = 5
    Setting[:account_lockout_window] = 15
    Setting[:account_lockout_duration] = 30
  end

  test 'no previous failures yields no failed-login notice session' do
    post :login, params: { login: { login: @user.login, password: @password } }
    assert_response :redirect
    assert_nil session[:failed_login_notice_count]
    event = UserLoginEvent.where(user_id: @user.id).recent_first.first
    assert_equal 0, event.failed_attempts_before_login
    assert_equal 0, @user.reload.failed_login_attempts
  end

  test 'three wrong passwords then success reports count 3 and resets lockout' do
    3.times { post :login, params: { login: { login: @user.login, password: 'wrong-password' } } }
    assert_equal 3, @user.reload.failed_login_attempts

    post :login, params: { login: { login: @user.login, password: @password } }
    assert_response :redirect
    assert_equal 3, session[:failed_login_notice_count]
    assert_equal @user.id, session[:failed_login_notice_user_id]

    event = UserLoginEvent.where(user_id: @user.id).recent_first.first
    assert_equal 3, event.failed_attempts_before_login
    assert_equal 0, @user.reload.failed_login_attempts
    assert_nil @user.failed_login_started_at
    assert_nil @user.locked_until
  end

  test 'captcha failure does not increase password failure count' do
    Setting[:captcha_enabled] = true
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    before = @user.failed_login_attempts.to_i
    post :login, params: { login: { login: @user.login, password: @password, captcha_response: 'bad' } }
    assert_equal before, @user.reload.failed_login_attempts
    assert_equal 0, UserLoginEvent.where(user_id: @user.id).count
  end

  test 'failed login does not queue authenticated notice' do
    post :login, params: { login: { login: @user.login, password: 'wrong-password' } }
    assert_nil session[:failed_login_notice_count]
    assert_redirected_to login_users_path
  end

  test 'reauthentication failure does not create login history notice' do
    post :login, params: { login: { login: @user.login, password: @password } }
    session.delete(:failed_login_notice_count)
    session.delete(:failed_login_notice_user_id)
    count = UserLoginEvent.where(user_id: @user.id).count

    post :reauthenticate,
         params: { password: 'wrong-password' },
         session: set_session_user(@user)
    assert_response :unauthorized
    assert_equal count, UserLoginEvent.where(user_id: @user.id).count
    assert_nil session[:failed_login_notice_count]
  end
end
