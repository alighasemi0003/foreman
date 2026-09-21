# frozen_string_literal: true

require 'test_helper'

# Phase 4: reauthentication endpoint + freshness — no sensitive-action gates.
class UsersControllerReauthenticationEndpointTest < ActionController::TestCase
  tests UsersController

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    Setting[:reauthentication_window_minutes] = 5
  end

  test 'POST reauthenticate with correct password marks session fresh' do
    User.expects(:try_to_login).never
    post :reauthenticate,
         params: { password: @password },
         session: { user: @user.id, expires_at: 5.minutes.from_now }
    assert_response :success
    body = ActiveSupport::JSON.decode(@response.body)
    assert_equal 'success', body['status']
    assert session[Foreman::Reauthentication::SESSION_AT].present?
    assert_equal @user.id, session[Foreman::Reauthentication::SESSION_ACTOR]
  end

  test 'POST reauthenticate with wrong password leaves session stale' do
    post :reauthenticate,
         params: { password: 'wrong-password' },
         session: { user: @user.id, expires_at: 5.minutes.from_now }
    assert_response :unauthorized
    body = ActiveSupport::JSON.decode(@response.body)
    assert_equal 'authentication_failed', body['status']
    refute session[Foreman::Reauthentication::SESSION_AT].present?
  end

  test 'POST reauthenticate accepts nested user password params' do
    post :reauthenticate,
         params: { user: { password: @password } },
         session: { user: @user.id, expires_at: 5.minutes.from_now }
    assert_response :success
    assert_equal @user.id, session[Foreman::Reauthentication::SESSION_ACTOR]
  end

  test 'POST reauthenticate without CSRF token is rejected' do
    ActionController::Base.allow_forgery_protection = true
    begin
      assert_raises ActionController::InvalidAuthenticityToken do
        post :reauthenticate,
             params: { password: @password },
             session: { user: @user.id, expires_at: 5.minutes.from_now }
      end
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end

  test 'POST reauthenticate for API session is unsupported' do
    post :reauthenticate,
         params: { password: @password },
         session: { user: @user.id, api_authenticated_session: true, expires_at: 5.minutes.from_now }
    assert_response :forbidden
  end

  test 'successful interactive login marks local user fresh and keeps Audit' do
    assert_difference -> { Audit.where(action: 'login').count } do
      post :login, params: { login: { login: @user.login, password: @password } }
    end
    assert_response :redirect
    assert session[Foreman::Reauthentication::SESSION_AT].present?
    assert_equal @user.id, session[Foreman::Reauthentication::SESSION_ACTOR]
  end

  test 'failed interactive login does not mark freshness' do
    post :login, params: { login: { login: @user.login, password: 'wrong' } }
    assert_redirected_to login_users_path
    refute session[Foreman::Reauthentication::SESSION_AT].present?
  end

  test 'logout clears reauthentication freshness' do
    post :logout, session: set_session_user(@user)
    assert_response :redirect
    refute session[Foreman::Reauthentication::SESSION_AT].present?
    refute session[Foreman::Reauthentication::SESSION_ACTOR].present?
  end

  test 'stop_impersonation clears reauthentication freshness' do
    admin = users(:admin)
    session_hash = {
      user: @user.id,
      impersonated_by: admin.id,
      expires_at: 5.minutes.from_now,
      Foreman::Reauthentication::SESSION_AT => Time.now.utc.to_i,
      Foreman::Reauthentication::SESSION_ACTOR => admin.id,
    }
    delete :stop_impersonation, session: session_hash
    assert_response :success
    refute session[Foreman::Reauthentication::SESSION_AT].present?
  end

  test 'external auth user reauthenticate returns unsupported' do
    external = users(:one)
    assert external.auth_source.is_a?(AuthSourceLdap) || external.auth_source.is_a?(AuthSourceExternal) || !external.internal?
    # Force external for this test if fixture is LDAP — create dedicated external user
    ext_source = AuthSourceExternal.find_or_create_by!(name: 'phase4-external-test')
    ext_user = FactoryBot.create(:user, :auth_source => ext_source, :password => nil)
    post :reauthenticate,
         params: { password: 'anything' },
         session: { user: ext_user.id, expires_at: 5.minutes.from_now }
    assert_response :unprocessable_entity
    body = ActiveSupport::JSON.decode(@response.body)
    assert_equal 'reauthentication_unsupported', body['status']
    refute session[Foreman::Reauthentication::SESSION_AT].present?
  end
end

class ReauthenticationSettingValidationTest < ActiveSupport::TestCase
  test 'reauthentication_window_minutes default and bounds' do
    assert_equal 5, Setting[:reauthentication_window_minutes]

    # Materialize the registry default into a DB row, then validate bounds.
    Setting[:reauthentication_window_minutes] = 5
    setting = Setting.find_by_name('reauthentication_window_minutes')
    assert setting, 'expected setting reauthentication_window_minutes'

    setting.value = 1
    assert_valid setting
    setting.value = 30
    assert_valid setting

    setting.value = 0
    refute setting.valid?
    setting.value = 31
    refute setting.valid?
    setting.value = -1
    refute setting.valid?
  end

  test 'require_reauth boolean settings exist with fail-secure defaults' do
    %w[
      require_reauth_users_set_admin
      require_reauth_users_create
      require_reauth_users_destroy
    ].each do |name|
      assert_equal true, Setting[name], "expected fail-secure default for #{name}"
      Setting[name] = true
      assert Setting.find_by_name(name), "expected setting #{name}"
    end
  end
end
