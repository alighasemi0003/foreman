# frozen_string_literal: true

require 'test_helper'

class BrowserSessionPolicyTest < ActionController::TestCase
  tests HostsController

  setup do
    Setting[:require_reauth_users_terminate_sessions] = false
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

  test 'second concurrent login remains valid while flag stays set' do
    @user.release_active_session
    session_a = login_session(@user)
    session_b = login_session(@user)
    assert @user.reload.has_active_session?

    get :index, session: session_a
    assert_response :success
    get :index, session: session_b
    assert_response :success
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

  test 'different users do not invalidate each other' do
    @user.release_active_session
    @other.release_active_session
    session_user = login_session(@user)
    session_other = login_session(@other)

    get :index, session: session_user
    assert_response :success
    get :index, session: session_other
    assert_response :success
    assert @user.reload.has_active_session?
    assert @other.reload.has_active_session?
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
    # JWT / Basic API are gated by ignore_api_request? / api_authenticated_session,
    # not the UI active-session flag. Covered by JwtUnaffectedTest below.
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
