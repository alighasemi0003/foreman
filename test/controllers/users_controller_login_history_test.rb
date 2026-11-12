# frozen_string_literal: true

require 'test_helper'

class UsersControllerLoginHistoryTest < ActionController::TestCase
  tests UsersController

  setup do
    UserLoginEvent.delete_all
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    Setting[:authorize_login_delegation] = false
    Setting[:login_history_limit] = 20
    Setting[:captcha_enabled] = false
  end

  test 'successful password login creates one history record' do
    @request.env['REMOTE_ADDR'] = '203.0.113.50'
    assert_difference -> { UserLoginEvent.where(user_id: @user.id).count }, 1 do
      post :login, params: { login: { login: @user.login, password: @password } }
    end
    assert_response :redirect
    event = UserLoginEvent.where(user_id: @user.id).recent_first.first
    assert_equal '203.0.113.50', event.remote_ip
    assert_equal 'password', event.auth_method
    assert_operator @user.reload.last_login_on.to_i, :>=, (Time.now.utc - 1.minute).to_i
  end

  test 'multiple successful logins create multiple ordered records' do
    post :login, params: { login: { login: @user.login, password: @password } }
    first_id = UserLoginEvent.where(user_id: @user.id).order(:id).last.id
    post :logout
    post :login, params: { login: { login: @user.login, password: @password } }
    events = UserLoginEvent.where(user_id: @user.id).recent_first.to_a
    assert_operator events.size, :>=, 2
    assert_operator events.first.logged_in_at, :>=, events.second.logged_in_at
    refute_equal first_id, events.first.id
  end

  test 'failed login creates no history record' do
    assert_no_difference -> { UserLoginEvent.count } do
      post :login, params: { login: { login: @user.login, password: 'wrong-password' } }
    end
  end

  test 'captcha failure creates no history record' do
    Setting[:captcha_enabled] = true
    Foreman::Captcha.stubs(:verify).returns(
      Foreman::Captcha::Result.new(status: :failed, message: 'captcha_failed')
    )
    assert_no_difference -> { UserLoginEvent.count } do
      post :login, params: { login: { login: @user.login, password: @password, captcha_response: 'bad' } }
    end
  end

  test 'page refresh with session does not create history' do
    post :login, params: { login: { login: @user.login, password: @password } }
    assert_equal 1, UserLoginEvent.where(user_id: @user.id).count
    get :index, session: set_session_user(@user)
    assert_equal 1, UserLoginEvent.where(user_id: @user.id).count
  end

  test 'reauthentication does not create login history' do
    post :login, params: { login: { login: @user.login, password: @password } }
    count = UserLoginEvent.where(user_id: @user.id).count
    post :reauthenticate,
         params: { password: @password },
         session: set_session_user(@user)
    assert_equal count, UserLoginEvent.where(user_id: @user.id).count
  end

  test 'history records contain no credentials' do
    post :login, params: { login: { login: @user.login, password: @password } }
    event = UserLoginEvent.where(user_id: @user.id).last
    dumped = event.attributes.to_json
    refute_includes dumped, @password
    refute_match(/password_hash|password_salt|Bearer |eyJ/, dumped)
  end
end
