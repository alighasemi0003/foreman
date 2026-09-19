# frozen_string_literal: true

require 'test_helper'

class UsersControllerCreateReauthenticationTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    @admin.update_column(:has_active_session, true)
    Setting[:require_reauth_users_create] = true
  end

  def create_params(overrides = {})
    {
      user: {
        login: "reauthcreate#{Foreman.uuid[0..7]}",
        mail: 'reauthcreate@example.com',
        auth_source_id: auth_sources(:internal).id,
        password: 'Password1!',
        password_confirmation: 'Password1!',
      }.merge(overrides),
    }
  end

  test 'create blocked when stale and user not persisted' do
    assert_no_difference('User.unscoped.count') do
      post :create, params: create_params, session: { user: @admin.id, expires_at: 5.minutes.from_now }
    end
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'create succeeds when fresh' do
    assert_difference('User.unscoped.count', 1) do
      post :create, params: create_params, session: set_session_user(@admin)
    end
    assert_redirected_to users_path
  end

  test 'create with admin flag needs only users.create reauth then succeeds' do
    login = "reauthadmin#{Foreman.uuid[0..7]}"
    assert_difference('User.unscoped.count', 1) do
      post :create, params: create_params(login: login, admin: true), session: set_session_user(@admin)
    end
    assert User.unscoped.find_by_login(login).admin?
  end

  test 'setting OFF allows create without recent auth after authorization' do
    Setting[:require_reauth_users_create] = false
    assert_difference('User.unscoped.count', 1) do
      post :create, params: create_params, session: { user: @admin.id, expires_at: 5.minutes.from_now }
    end
  end

  test 'unauthorized viewer cannot create even with fresh session' do
    viewer = users(:one)
    viewer.update_column(:has_active_session, true)
    assert_no_difference('User.unscoped.count') do
      post :create, params: create_params, session: set_session_user(viewer)
    end
    assert_includes [403, 404], response.status
  end

  test 'fresh reauth does not bypass password complexity' do
    assert_no_difference('User.unscoped.count') do
      post :create, params: create_params(password: 'weakpass', password_confirmation: 'weakpass'),
                    session: set_session_user(@admin)
    end
    assert_template :new
  end
end
