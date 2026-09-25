# frozen_string_literal: true

require 'test_helper'

class UsersControllerCreateReauthenticationTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
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
        password_change_required: true,
      }.merge(overrides),
    }
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  test 'create blocked when stale and user not persisted' do
    assert_no_difference('User.unscoped.count') do
      post :create, params: create_params, session: stale_session
    end
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'create with X-Foreman-Accept-Reauth returns structured JSON 403 when stale' do
    @request.headers['X-Foreman-Accept-Reauth'] = '1'
    assert_no_difference('User.unscoped.count') do
      post :create, params: create_params, session: stale_session
    end
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'users.create', body.dig('error', 'action')
    assert_nil flash[:error]
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
      post :create, params: create_params, session: stale_session
    end
  end

  test 'unauthorized viewer cannot create even with fresh session' do
    viewer = users(:one)
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

  test 'create persists password_change_required when checked' do
    login = "forcepw#{Foreman.uuid[0..7]}"
    post :create, params: create_params(login: login, password_change_required: true),
                  session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    assert user.password_change_required?
  end

  test 'create persists password_change_required false when unchecked' do
    login = "noforce#{Foreman.uuid[0..7]}"
    post :create, params: create_params(login: login, password_change_required: false),
                  session: set_session_user(@admin)
    user = User.unscoped.find_by_login(login)
    assert user
    refute user.password_change_required?
  end
end
