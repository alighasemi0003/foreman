# frozen_string_literal: true

require 'test_helper'

class Api::V2::SettingsControllerReauthenticationTest < ActionController::TestCase
  tests Api::V2::SettingsController

  setup do
    User.current = users(:admin)
    @request.session[:user] = users(:admin).id
    @request.session[:expires_at] = 5.minutes.from_now.to_i
    @request.session[:api_authenticated_session] = false
    reset_api_credentials
    # Encrypted oauth_* settings need a key (F-004); stub for reauth policy tests.
    Setting.any_instance.stubs(:encryption_key).returns('25d224dd383e92a7e0c82b8bf7c985e8')
  end

  test 'updating reauth window without recent auth is blocked' do
    put :update, params: { id: 'reauthentication_window_minutes', setting: { value: '10' } }
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 5, Setting[:reauthentication_window_minutes]
  end

  test 'updating reauth window with recent auth succeeds' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = users(:admin).id
    put :update, params: { id: 'reauthentication_window_minutes', setting: { value: '10' } }
    assert_response :success
    assert_equal 10, Setting[:reauthentication_window_minutes]
  end

  test 'non-meta setting update without recent auth is allowed' do
    put :update, params: { id: 'entries_per_page', setting: { value: '25' } }
    assert_response :success
  end

  test 'oauth consumer secret update without recent auth is blocked' do
    put :update, params: { id: 'oauth_consumer_secret', setting: { value: 'new-secret-value' } }
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'settings.oauth_credentials.update', body.dig('error', 'action')
  end

  test 'oauth consumer key update with recent auth succeeds' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = users(:admin).id
    put :update, params: { id: 'oauth_consumer_key', setting: { value: 'new-consumer-key' } }
    assert_response :success
    assert_equal 'new-consumer-key', Setting[:oauth_consumer_key]
  end

  test 'require_reauth toggle cannot disable its own meta protection when stale' do
    put :update, params: { id: 'require_reauth_users_create', setting: { value: 'false' } }
    assert_response :forbidden
    assert_equal true, Setting[:require_reauth_users_create]
  end

  test 'machine api session can update oauth credentials without browser freshness' do
    @request.session[:api_authenticated_session] = true
    put :update, params: { id: 'oauth_consumer_key', setting: { value: 'machine-key' } }
    assert_response :success
    assert_equal 'machine-key', Setting[:oauth_consumer_key]
  end

  test 'admin cannot disable mandatory reauth policy setting even when fresh' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = users(:admin).id
    put :update, params: {
      id: 'require_reauth_settings_reauthentication_policy',
      setting: { value: 'false' },
    }
    assert_response :unprocessable_entity
    assert_match(/mandatory/i, JSON.parse(@response.body).dig('error', 'message').to_s)
    assert_equal true, Setting[:require_reauth_settings_reauthentication_policy]
  end

  test 'admin can disable a registered optional reauth toggle when fresh' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = users(:admin).id
    Setting[:require_reauth_hosts_console] = true
    put :update, params: { id: 'require_reauth_hosts_console', setting: { value: 'false' } }
    assert_response :success
    assert_equal false, Setting[:require_reauth_hosts_console]
    refute Foreman::Reauthentication.policy_enabled?('hosts.console')
  ensure
    Setting[:require_reauth_hosts_console] = true
  end

  test 'reauthentication policy settings live in dedicated category' do
    get :show, params: { id: 'require_reauth_users_impersonate' }
    assert_response :success
    body = JSON.parse(@response.body)
    assert_equal 'reauthentication', body['category']
    assert_match(/Re-authentication policy/i, body['category_name'].to_s)
  end

  test 'mandatory policy setting is readonly in API presentation' do
    get :show, params: { id: 'require_reauth_settings_oauth_credentials' }
    assert_response :success
    body = JSON.parse(@response.body)
    assert_equal true, body['readonly']
    assert_equal true, body['value'] == true || body['value'] == 'true'
  end
end
