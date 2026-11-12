# frozen_string_literal: true

require 'test_helper'

class UsersControllerLoginHistoryUiTest < ActionController::TestCase
  tests UsersController

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    @other = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    UserLoginEvent.delete_all
    Setting[:login_history_limit] = 5
  end

  test 'self can view empty login history' do
    get :login_history, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    assert_match(/No login history yet/, response.body)
  end

  test 'self sees own events with ip host auth and failed attempts' do
    UserLoginEvent.record_successful_login!(
      user: @user,
      remote_ip: '203.0.113.10',
      request_host: 'foreman.example.com',
      auth_method: 'password',
      auth_source_name: 'Internal',
      failed_attempts_before_login: 2
    )
    UserLoginEvent.record_successful_login!(
      user: @user,
      remote_ip: '198.51.100.20',
      request_host: "evil\n<script>host",
      auth_method: 'password',
      failed_attempts_before_login: 0
    )

    get :login_history, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    assert_includes response.body, '203.0.113.10'
    assert_includes response.body, 'foreman.example.com'
    assert_includes response.body, '198.51.100.20'
    assert_includes response.body, 'Password (local)'
    assert_match(/>\s*2\s*</, response.body)
    refute_includes response.body, '<script>'
    assert_includes response.body, 'Foreman application host'
  end

  test 'events are ordered recent first' do
    older = UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.1')
    sleep 0.05
    newer = UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.2')
    get :login_history, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    body = response.body
    assert_operator body.index('203.0.113.2'), :<, body.index('203.0.113.1')
    assert_equal newer.id, @user.login_events.recent_first.first.id
    assert_equal older.id, @user.login_events.recent_first.last.id
  end

  test 'user cannot view another users login history' do
    UserLoginEvent.record_successful_login!(user: @other, remote_ip: '203.0.113.99')
    get :login_history, params: { id: @other.id }, session: set_session_user(@user)
    assert_response :forbidden
    refute_includes response.body, '203.0.113.99'
  end

  test 'admin with view_users can view another users history' do
    UserLoginEvent.record_successful_login!(
      user: @other,
      remote_ip: '203.0.113.55',
      request_host: 'foreman.example.com',
      failed_attempts_before_login: 1
    )
    get :login_history, params: { id: @other.id }, session: set_session_user(users(:admin))
    assert_response :success
    assert_includes response.body, '203.0.113.55'
  end

  test 'unauthenticated request is redirected to login' do
    get :login_history, params: { id: @user.id }
    assert_redirected_to login_users_path
  end

  test 'forced password change cannot access login history' do
    @user.update_column(:password_change_required, true)
    get :login_history, params: { id: @user.id }, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
  end

  test 'my account edit shows login history tab preview' do
    UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.77')
    get :edit, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    assert_includes response.body, 'login_history'
    assert_includes response.body, '203.0.113.77'
    assert_includes response.body, login_history_user_path(@user)
  end

  test 'retention limit hides overflow from UI listing' do
    Setting[:login_history_limit] = 3
    5.times do |i|
      UserLoginEvent.record_successful_login!(user: @user, remote_ip: "203.0.113.#{i}")
    end
    assert_equal 3, @user.login_events.count
    get :login_history, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    assert_includes response.body, '203.0.113.4'
    refute_includes response.body, '203.0.113.0'
  end

  test 'failed login notice consumption still works independently' do
    session_data = set_session_user(@user).merge(
      failed_login_notice_count: 2,
      failed_login_notice_user_id: @user.id
    )
    get :edit, params: { id: @user.id }, session: session_data
    assert_response :success
    assert_match(/2 failed login attempt/, response.body)
    assert_nil session[:failed_login_notice_count]
  end
end
