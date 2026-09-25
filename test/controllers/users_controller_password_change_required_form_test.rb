# frozen_string_literal: true

require 'test_helper'

class UsersControllerPasswordChangeRequiredFormTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_users_create] = false
  end

  test 'new local user form renders password_change_required checkbox checked by default' do
    get :new, session: set_session_user(@admin)
    assert_response :success
    # checkbox_f emits hidden "0" + checkbox "1"
    assert_select 'input[type=checkbox][name=?]', 'user[password_change_required]', count: 1
    assert_select 'input[type=checkbox][name=?][checked]', 'user[password_change_required]'
    assert_select 'input[type=hidden][name=?][value=?]', 'user[password_change_required]', '0'
    assert_select 'label', text: /Require password change on next login/
    assert assigns(:user).password_change_required?
    assert assigns(:user).auth_source.is_a?(AuthSourceInternal)
  end

  test 'create with checkbox checked persists true' do
    login = "pcrform#{Foreman.uuid[0..7]}"
    post :create, params: {
      user: {
        login: login,
        mail: "#{login}@example.com",
        auth_source_id: auth_sources(:internal).id,
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: '1',
      },
    }, session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    assert user.password_change_required?
  end

  test 'create with checkbox unchecked persists false' do
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
    refute user.password_change_required?
  end

  test 'existing users keep DB default false when built without flag' do
    user = FactoryBot.build(:user, :with_mail, auth_source: auth_sources(:internal))
    assert_equal false, user.password_change_required
  end

  test 'LDAP create cannot keep forced password change' do
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
