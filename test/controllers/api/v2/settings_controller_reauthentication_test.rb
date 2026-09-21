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
end
