# frozen_string_literal: true

require 'test_helper'

class PasswordExpirationEnforcementTest < ActionController::TestCase
  tests DashboardController
  include ActiveSupport::Testing::TimeHelpers

  setup do
    Setting[:require_reauth_users_change_password] = false
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    Setting[:password_max_age] = 30
    @user.update_columns(password_changed_at: 40.days.ago.utc)
  end

  teardown do
    Setting[:password_max_age] = 0
  end

  test 'expired interactive session cannot browse dashboard' do
    get :index, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
    assert_match(/expired/i, flash[:warning].to_s)
  end

  test 'fresh password can browse dashboard' do
    @user.update_columns(password_changed_at: Time.now.utc)
    get :index, session: set_session_user(@user)
    assert_response :success
  end
end

class PasswordExpirationUsersControllerTest < ActionController::TestCase
  tests UsersController
  include ActiveSupport::Testing::TimeHelpers

  setup do
    Setting[:require_reauth_users_change_password] = false
    UserLoginEvent.delete_all if defined?(UserLoginEvent)
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    Setting[:password_max_age] = 30
    @user.update_columns(password_changed_at: 40.days.ago.utc)
    Setting[:authorize_login_delegation] = false
    Setting[:captcha_enabled] = false
  end

  teardown do
    Setting[:password_max_age] = 0
  end

  test 'login with expired password redirects to forced change form' do
    post :login, params: { login: { login: @user.login, password: @password } }
    assert_redirected_to edit_user_path(@user)
    assert_match(/expired/i, flash[:warning].to_s)
  end

  test 'expired user edit uses minimal password form' do
    get :edit, params: { id: @user.id }, session: set_session_user(@user)
    assert_response :success
    assert_template :password_change_required
  end

  test 'successful renewal logs out and clears expiration' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: @password,
            password: 'Password2!',
            password_confirmation: 'Password2!'
          }
        },
        session: set_session_user(@user)
    assert_redirected_to login_users_path
    assert_nil session[:user]
    @user.reload
    refute @user.password_expired?
    assert_in_delta Time.now.utc.to_i, @user.password_changed_at.to_i, 5
  end

  test 'failed renewal keeps expired state' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: @password,
            password: @password,
            password_confirmation: @password
          }
        },
        session: set_session_user(@user)
    assert_template :password_change_required
    assert @user.reload.password_expired?
  end
end

class PasswordExpirationApiGateTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    Setting[:password_max_age] = 30
    @user.update_columns(password_changed_at: 40.days.ago.utc)
  end

  teardown do
    Setting[:password_max_age] = 0
  end

  test 'interactive session API is forbidden when password expired' do
    get :index, session: set_session_user(@user)
    assert_response :forbidden
  end
end
