# frozen_string_literal: true

require 'test_helper'

class UsersControllerPasswordChangeRequiredFormTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_users_create] = false
  end

  test 'new local user form does not render password_change_required checkbox' do
    get :new, session: set_session_user(@admin)
    assert_response :success
    assert_select 'input[type=checkbox][name=?]', 'user[password_change_required]', count: 0
    assert_select 'input[type=hidden][name=?]', 'user[password_change_required]', count: 0
    refute_match(/Require password change on next login/, response.body)
    assert_select 'input[name=?]', 'user[login]'
    assert_select 'input[name=?]', 'user[mail]'
    assert_match(/user\[password\]/, response.body)
    assert_match(/PasswordStrength|user\[password_confirmation\]/, response.body)
    assert assigns(:user).password_change_required?
    assert assigns(:user).auth_source.is_a?(AuthSourceInternal)
  end

  test 'create without force parameter still enables mandatory password change' do
    login = "pcrform#{Foreman.uuid[0..7]}"
    post :create, params: {
      user: {
        login: login,
        mail: "#{login}@example.com",
        auth_source_id: auth_sources(:internal).id,
        password: 'Password1!',
        password_confirmation: 'Password1!',
      },
    }, session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    assert user.password_change_required?
  end

  test 'create with forged force=false still enables mandatory password change' do
    login = "pcrform0#{Foreman.uuid[0..7]}"
    post :create, params: {
      user: {
        login: login,
        mail: "#{login}@example.com",
        auth_source_id: auth_sources(:internal).id,
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: '0',
      },
    }, session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    assert user.password_change_required?
  end

  test 'edit form does not render password_change_required checkbox' do
    user = FactoryBot.create(:user, :with_mail, auth_source: auth_sources(:internal))
    get :edit, params: { id: user.id }, session: set_session_user(@admin)
    assert_response :success
    assert_select 'input[type=checkbox][name=?]', 'user[password_change_required]', count: 0
    refute_match(/Require password change on next login/, response.body)
  end

  test 'LDAP create never enables forced password change' do
    ldap = FactoryBot.create(:auth_source_ldap)
    login = "pcrldap#{Foreman.uuid[0..7]}"
    post :create, params: {
      user: {
        login: login,
        mail: "#{login}@example.com",
        auth_source_id: ldap.id,
        password_change_required: '1',
      },
    }, session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    refute user.password_change_required?
  end
end
