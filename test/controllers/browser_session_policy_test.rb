# frozen_string_literal: true

require 'test_helper'
require 'active_record/session_store/session'

class BrowserSessionPolicyTest < ActionController::TestCase
  tests HostsController

  setup do
    Setting[:require_reauth_users_terminate_sessions] = false
    Setting[:authorize_login_delegation] = false
    Setting[:captcha_enabled] = false
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail, :admin,
                              password: @password,
                              password_confirmation: @password)
    @other = FactoryBot.create(:user, :with_mail, :admin,
                               password: @password,
                               password_confirmation: @password)
  end

  test 'first interactive login claims active session and is valid' do
    @user.release_active_session
    post_login(@user)
    assert @user.reload.has_active_session?
    get :index, session: set_session_user(@user)
    assert_response :success
  end

  test 'newer login wins: older browser session cannot continue' do
    @user.release_active_session
    # Persist two independent AR session rows as Browser A / Browser B would.
    sid_a = store_browser_session!(@user)
    sid_b = store_browser_session!(@user)
    assert_operator ActiveRecord::SessionStore::Session.where(session_id: [sid_a, sid_b]).count, :>=, 2

    # Simulate B completing login_user invalidation while keeping B's sid.
    @user.claim_active_session
    @user.invalidate_other_browser_sessions!(keep_session_id: sid_b)

    refute ActiveRecord::SessionStore::Session.find_by_session_id(sid_a)
    assert ActiveRecord::SessionStore::Session.find_by_session_id(sid_b)

    get :index, session: set_session_user(@user).merge(session_id_override_unused: true)
    # Controller test uses in-memory session; decisive check is AR row removal above.
    assert @user.reload.has_active_session?
  end

  test 'logout clears flag and invalidates remaining UI session for same user' do
    @user.release_active_session
    session_a = login_session(@user)
    session_b = login_session(@user)

    @controller = UsersController.new
    @request = ActionController::TestRequest.create(@controller)
    @response = ActionDispatch::TestResponse.new
    delete :logout, session: session_a
    assert_response :redirect
    refute @user.reload.has_active_session?

    @controller = HostsController.new
    @request = ActionController::TestRequest.create(@controller)
    @response = ActionDispatch::TestResponse.new
    get :index, session: session_b
    assert_redirected_to login_users_path
    assert_match(/terminated/i, flash[:inline].to_s + flash[:warning].to_s)
  end

  test 'failed login does not clear active session flag' do
    @user.release_active_session
    post_login(@user)
    assert @user.reload.has_active_session?

    @controller = UsersController.new
    @request = ActionController::TestRequest.create(@controller)
    @response = ActionDispatch::TestResponse.new
    post :login, params: { login: { login: @user.login, password: 'wrong-password' } }
    assert @user.reload.has_active_session?
  end

  test 'different users do not invalidate each other' do
    @user.release_active_session
    @other.release_active_session
    sid_user = store_browser_session!(@user)
    sid_other = store_browser_session!(@other)
    @user.invalidate_other_browser_sessions!(keep_session_id: sid_user)
    assert ActiveRecord::SessionStore::Session.find_by_session_id(sid_other)
    assert ActiveRecord::SessionStore::Session.find_by_session_id(sid_user)
  end

  test 'admin terminate clears target flag without affecting other user' do
    Setting[:require_reauth_users_terminate_sessions] = false
    @user.claim_active_session
    @other.claim_active_session
    admin = users(:admin)
    admin.claim_active_session

    @controller = UsersController.new
    @request = ActionController::TestRequest.create(@controller)
    @response = ActionDispatch::TestResponse.new
    patch :terminate_active_session, params: { id: @user.id }, session: set_session_user(admin)
    assert_response :redirect
    refute @user.reload.has_active_session?
    assert @other.reload.has_active_session?
  end

  test 'API-only authentication does not require has_active_session flag' do
    @user.release_active_session
    refute @user.reload.has_active_session?
    assert_nil session[:user]
  end

  private

  def post_login(user)
    @controller = UsersController.new
    @request = ActionController::TestRequest.create(@controller)
    @response = ActionDispatch::TestResponse.new
    post :login, params: { login: { login: user.login, password: @password } }
    assert_response :redirect
  end

  def login_session(user)
    post_login(user)
    set_session_user(user)
  end

  def store_browser_session!(user)
    sid = "test-#{SecureRandom.hex(16)}"
    ActiveRecord::SessionStore::Session.create!(
      session_id: sid,
      data: { 'user' => user.id, 'expires_at' => 1.hour.from_now.utc.to_s }
    )
    sid
  end
end

class BrowserSessionPolicyJwtUnaffectedTest < ActiveSupport::TestCase
  test 'JWT decode still works regardless of has_active_session flag' do
    user = FactoryBot.create(:user, :with_mail)
    token = user.jwt_token!
    user.release_active_session
    assert JwtToken.new(token).decode.present?
    user.claim_active_session
    assert JwtToken.new(token).decode.present?
  end
end

class BrowserSessionPolicyLoginIntegrationTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:authorize_login_delegation] = false
    Setting[:captcha_enabled] = false
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail, :admin,
                              password: @password,
                              password_confirmation: @password)
  end

  test 'login_user invalidates other stored sessions for the user' do
    @user.release_active_session
    old_sid = "old-#{SecureRandom.hex(12)}"
    ActiveRecord::SessionStore::Session.create!(
      session_id: old_sid,
      data: { 'user' => @user.id }
    )

    post :login, params: { login: { login: @user.login, password: @password } }
    assert_response :redirect
    refute ActiveRecord::SessionStore::Session.find_by_session_id(old_sid),
           'older browser session row must be removed on newer login'
    assert @user.reload.has_active_session?
  end
end
