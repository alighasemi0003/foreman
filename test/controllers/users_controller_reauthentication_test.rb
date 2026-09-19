# frozen_string_literal: true

require 'test_helper'

class UsersControllerReauthenticationTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    @admin.update_column(:has_active_session, true)
    @target = FactoryBot.create(:user, :with_mail, firstname: 'Original')
    Setting[:require_reauth_users_set_admin] = true
    Setting[:require_reauth_users_set_disabled] = true
    Setting[:require_reauth_users_impersonate] = true
    Setting[:reauthentication_window_minutes] = 5
  end

  def stale_session(user = @admin)
    user.update_column(:has_active_session, true)
    { user: user.id, expires_at: 5.minutes.from_now }
  end

  def fresh_session(user = @admin)
    set_session_user(user)
  end

  test 'normal user field update does not require reauth when stale' do
    put :update, params: { id: @target.id, user: { firstname: 'ChangedName' } }, session: stale_session
    assert_response :redirect
    assert_redirected_to users_path
    assert_equal 'ChangedName', @target.reload.firstname
  end

  test 'admin transition without recent auth is blocked and not persisted' do
    refute @target.admin?
    put :update, params: { id: @target.id, user: { admin: true, firstname: @target.firstname } },
                 session: stale_session
    assert_response :redirect
    refute @target.reload.admin?
    assert_equal 'Original', @target.firstname
  end

  test 'admin transition allowed when recently authenticated' do
    put :update, params: { id: @target.id, user: { admin: true } }, session: fresh_session
    assert_response :redirect
    assert @target.reload.admin?
  end

  test 'disabled transition without recent auth is blocked' do
    put :update, params: { id: @target.id, user: { disabled: true } }, session: stale_session
    assert_response :redirect
    refute @target.reload.disabled?
  end

  test 'setting OFF allows admin change without recent auth' do
    Setting[:require_reauth_users_set_admin] = false
    put :update, params: { id: @target.id, user: { admin: true } }, session: stale_session
    assert_response :redirect
    assert @target.reload.admin?
  end

  test 'impersonate without recent auth is blocked' do
    post :impersonate, params: { id: @target.id }, session: stale_session
    assert_response :redirect
    assert_nil session[:impersonated_by]
  end

  test 'impersonate with recent auth succeeds for real admin' do
    post :impersonate, params: { id: @target.id }, session: fresh_session
    assert_response :redirect
    assert_equal @admin.id, session[:impersonated_by]
    assert_equal @target.id, session[:user]
  end

  test 'reauthenticate with correct password marks session fresh' do
    # Fixture admin password is "secret" — same top-level JSON shape as the React modal
    post :reauthenticate, params: { password: 'secret' }, session: stale_session, as: :json
    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert session[:reauthenticated_at].present?
    assert_equal @admin.id, session[:reauth_actor_id]
  end

  test 'reauthenticate with wrap_parameters nested user.password succeeds' do
    post :reauthenticate, params: { user: { password: 'secret' } }, session: stale_session, as: :json
    assert_response :success
    assert session[:reauthenticated_at].present?
    assert_equal @admin.id, session[:reauth_actor_id]
  end

  test 'reauthenticate does not use try_to_login' do
    User.expects(:try_to_login).never
    post :reauthenticate, params: { password: 'secret' }, session: stale_session, as: :json
    assert_response :success
  end

  test 'reauthenticate with wrong password fails' do
    post :reauthenticate, params: { password: 'WrongPass1!' }, session: stale_session, as: :json
    assert_response :unauthorized
    assert_nil session[:reauthenticated_at]
  end

  test 'stop impersonation clears reauth state' do
    @target.update_column(:has_active_session, true)
    delete :stop_impersonation, session: {
      user: @target.id,
      impersonated_by: @admin.id,
      reauthenticated_at: Time.now.utc.to_i,
      reauth_actor_id: @admin.id,
      expires_at: 5.minutes.from_now,
    }
    assert_response :success
    assert_nil session[:reauthenticated_at]
    assert_nil session[:reauth_actor_id]
  end

  test 'expired recent auth blocks admin change' do
    @admin.update_column(:has_active_session, true)
    put :update, params: { id: @target.id, user: { admin: true } },
                 session: {
                   user: @admin.id,
                   reauthenticated_at: 10.minutes.ago.to_i,
                   reauth_actor_id: @admin.id,
                   expires_at: 5.minutes.from_now,
                 }
    assert_response :redirect
    refute @target.reload.admin?
  end

  test 'admin true to false requires reauth when stale' do
    @target.update_column(:admin, true)
    put :update, params: { id: @target.id, user: { admin: false } }, session: stale_session
    assert_response :redirect
    assert @target.reload.admin?
  end

  test 'disabled true to false requires reauth when stale' do
    @target.update_column(:disabled, true)
    put :update, params: { id: @target.id, user: { disabled: false } }, session: stale_session
    assert_response :redirect
    assert @target.reload.disabled?
  end

  test 'destroy without recent auth is blocked' do
    delete :destroy, params: { id: @target.id }, session: stale_session
    assert_response :redirect
    assert User.unscoped.exists?(@target.id)
  end

  test 'destroy with recent auth succeeds' do
    delete :destroy, params: { id: @target.id }, session: fresh_session
    assert_response :redirect
    refute User.unscoped.exists?(@target.id)
  end

  test 'unauthorized user cannot destroy even with fresh session' do
    viewer = users(:one)
    viewer.update_column(:has_active_session, true)
    delete :destroy, params: { id: @target.id }, session: set_session_user(viewer)
    assert_includes [403, 404], response.status
    assert User.unscoped.exists?(@target.id)
  end

  test 'other user password change blocked when stale and not persisted' do
    old_hash = @target.password_hash
    put :update, params: {
      id: @target.id,
      user: { password: 'Newpass1!', password_confirmation: 'Newpass1!', firstname: 'NoPersist' },
    }, session: stale_session
    assert_response :redirect
    @target.reload
    assert_equal old_hash, @target.password_hash
    assert_equal 'Original', @target.firstname
  end

  test 'self password change is not blocked by reauth gate when stale' do
    put :update, params: {
      id: @admin.id,
      user: {
        current_password: 'secret',
        password: 'Password1!',
        password_confirmation: 'Password1!',
      },
    }, session: stale_session(@admin)
    refute_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'role assignment blocked when stale' do
    role = Role.find_by_name('Viewer')
    original = @target.role_ids.sort
    put :update, params: { id: @target.id, user: { role_ids: (original + [role.id]).uniq } },
                 session: stale_session
    assert_response :redirect
    assert_equal original, @target.reload.role_ids.sort
  end

  test 'terminate session blocked when stale' do
    @target.update_column(:has_active_session, true)
    delete :terminate_active_session, params: { id: @target.id }, session: stale_session
    assert_response :redirect
    assert @target.reload.has_active_session?
  end

  test 'invalidate_jwt blocked when stale' do
    secret = @target.jwt_secret || FactoryBot.create(:jwt_secret, :user => @target)
    secret_id = secret.id
    delete :invalidate_jwt, params: { id: @target.id }, session: stale_session
    assert_response :redirect
    assert JwtSecret.exists?(secret_id)
  end

  context 'CSRF on reauthenticate' do
    setup do
      ActionController::Base.allow_forgery_protection = true
    end

    teardown do
      ActionController::Base.allow_forgery_protection = false
    end

    test 'reauthenticate requires CSRF token for browser session' do
      assert_raises ActionController::InvalidAuthenticityToken do
        post :reauthenticate, params: { password: 'secret' }, session: stale_session
      end
    end
  end
end
