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

  test 'forced user update own password clears flag' do
    user = create_local_user!(force: true)
    as_user user do
      put :update, params: {
        id: user.id,
        user: {
          current_password: 'Password1!',
          password: 'Password2!',
          password_confirmation: 'Password2!',
        },
      }, session: set_session_user(user)
    end
    user.reload
    refute user.password_change_required?
  end

  test 'forced user failed password update keeps flag' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'weak',
        password_confirmation: 'weak',
      },
    }, session: set_session_user(user)
    user.reload
    assert user.password_change_required?
  end

  test 'forced user cannot reuse current password and keeps flag' do
    user = create_local_user!(force: true)
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
    refute_match(/Password1!/, response.body)
    # Forced-change UX: minimal password form, not the full multi-tab edit UI
    assert_match(/Change your password|Password change required/i, response.body)
    refute_match(/Registration Tokens|Personal Access Tokens|SSH Keys/i, response.body)
    user.reload
    assert user.password_change_required?
    assert user.matching_password?('Password1!')
  end

  test 'forced user edit page uses minimal password form' do
    user = create_local_user!(force: true)
    get :edit, params: { id: user.id }, session: set_session_user(user)
    assert_response :success
    assert_match(/Change your password|Password change required/i, response.body)
    refute_match(/Registration Tokens|Personal Access Tokens/i, response.body)
    assert_select 'input[name=?]', 'user[current_password]'
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

  test 'forced user different password clears flag' do
    user = create_local_user!(force: true)
    put :update, params: {
      id: user.id,
      user: {
        current_password: 'Password1!',
        password: 'Password2!',
        password_confirmation: 'Password2!',
      },
    }, session: set_session_user(user)
    assert_response :redirect
    user.reload
    refute user.password_change_required?
    assert user.matching_password?('Password2!')
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
end
