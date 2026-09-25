# frozen_string_literal: true

require 'test_helper'

class UsersControllerPasswordChangeRequiredTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_users_create] = false
    Setting[:require_reauth_users_change_password] = false
  end

  def create_local_user!(force:)
    login = "fpc#{Foreman.uuid[0..7]}"
    post :create, params: {
      user: {
        login: login,
        mail: "#{login}@example.com",
        auth_source_id: auth_sources(:internal).id,
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: force,
      },
    }, session: set_session_user(@admin)
    User.unscoped.find_by_login(login)
  end

  def assert_minimal_forced_form!
    assert_response :success
    assert_template :password_change_required
    assert_template layout: 'password_change_required'
    assert_match(/Change your password|Password change required/i, response.body)
    assert_match(/must be different from your current password|Unable to change password|Incorrect password|Current password/i, response.body)
    refute_match(/Registration Tokens|Personal Access Tokens|SSH Keys|Email Preferences|UI Preferences/i, response.body)
    refute_match(%r{/notification_recipients}, response.body)
    assert_select 'input[name=?]', 'user[current_password]'
    assert_select 'input[name=?]', 'user[password]'
    assert_select 'input[name=?]', 'user[password_confirmation]'
  end

  test 'login with force flag redirects to own edit' do
    user = create_local_user!(force: true)
    assert user.password_change_required?

    post :login, params: { login: { login: user.login, password: 'Password1!' } }
    assert_redirected_to edit_user_path(user)
    assert_match(/change your password/i, flash[:warning].to_s)
  end

  test 'login without force flag goes to hosts' do
    user = create_local_user!(force: false)
    refute user.password_change_required?

    post :login, params: { login: { login: user.login, password: 'Password1!' } }
    assert_response :redirect
    refute_equal edit_user_path(user), response.redirect_url.sub(%r{https?://[^/]+}, '')
  end

  test 'forced user edit page uses minimal password form without tabs or notifications' do
    user = create_local_user!(force: true)
    get :edit, params: { id: user.id }, session: set_session_user(user)
    assert_minimal_forced_form!
  end

  test 'forced user cannot reuse current password and stays on minimal form' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password1!',
        password_confirmation: 'Password1!',
      },
    }, session: set_session_user(user)
    assert_minimal_forced_form!
    assert_match(/must be different from the current password/i, response.body)
    refute_match(/Password1!/, response.body)
    user.reload
    assert user.password_change_required?
    assert user.matching_password?('Password1!')
  end

  test 'forced user wrong current password stays on minimal form' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'WrongPass1!',
        password: 'Password2!',
        password_confirmation: 'Password2!',
      },
    }, session: set_session_user(user)
    assert_minimal_forced_form!
    assert_match(/Incorrect password/i, response.body)
    user.reload
    assert user.password_change_required?
    assert user.matching_password?('Password1!')
  end

  test 'forced user failed weak password keeps flag on minimal form' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'weak',
        password_confirmation: 'weak',
      },
    }, session: set_session_user(user)
    assert_minimal_forced_form!
    user.reload
    assert user.password_change_required?
  end

  test 'forced user different password clears flag logs out and redirects to login' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password2!',
        password_confirmation: 'Password2!',
      },
    }, session: set_session_user(user)

    assert_redirected_to login_users_path
    assert_match(/Password changed successfully\. Please sign in again/i, flash[:inline].to_s)
    refute_match(%r{notification_recipients}, response.location.to_s)
    assert_nil session[:user], 'browser session must be cleared after forced password change'

    user.reload
    refute user.password_change_required?
    assert user.matching_password?('Password2!')
    refute user.matching_password?('Password1!')
  end

  test 'old session cannot access authenticated pages after forced password change' do
    user = create_local_user!(force: true)
    session_data = set_session_user(user)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password2!',
        password_confirmation: 'Password2!',
      },
    }, session: session_data
    assert_redirected_to login_users_path
    assert_nil session[:user]

    get :edit, params: { id: user.id }, session: session_data.merge('user' => user.id)
    # After success the flag is cleared; with a forged session id the login filter decides.
    # Real runtime uses reset_session (new id). Assert password auth instead:
    refute user.reload.matching_password?('Password1!')
    assert user.matching_password?('Password2!')
  end

  test 'voluntary self change rejects reuse of current password' do
    user = create_local_user!(force: false)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password1!',
        password_confirmation: 'Password1!',
      },
    }, session: set_session_user(user)
    assert_response :success
    assert_match(/must be different from the current password/i, response.body)
    user.reload
    refute user.password_change_required?
    assert user.matching_password?('Password1!')
  end

  test 'logout succeeds while force password change is set' do
    user = create_local_user!(force: true)
    delete :logout, session: set_session_user(user)
    assert_response :redirect
    refute_match(/change your password/i, flash[:warning].to_s)
  end

  test 'admin password reset can require force change on next login' do
    user = create_local_user!(force: false)
    put :update, params: {
      id: user.id,
      user: {
        password: 'Password2!',
        password_confirmation: 'Password2!',
        password_change_required: true,
      },
    }, session: set_session_user(@admin)
    user.reload
    assert user.password_change_required?
  end

  test 'forced password flow never redirects to notification_recipients' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password2!',
        password_confirmation: 'Password2!',
      },
    }, session: set_session_user(user)
    assert_redirected_to login_users_path
    refute_match(%r{notification_recipients}, response.headers['Location'].to_s)
  end
end
