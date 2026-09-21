# frozen_string_literal: true

require 'test_helper'

class Api::V2::PersonalAccessTokensControllerReauthenticationTest < ActionController::TestCase
  tests Api::V2::PersonalAccessTokensController

  setup do
    @admin = users(:admin)
    @user = FactoryBot.create(:user, :with_mail)
    Setting[:require_reauth_personal_access_tokens_create] = true
    Setting[:require_reauth_personal_access_tokens_revoke] = true
    reset_api_credentials
    @request.session[:user] = @admin.id
    @request.session[:expires_at] = 5.minutes.from_now.to_i
    @request.session[:api_authenticated_session] = false
    User.current = @admin
  end

  test 'create blocked when stale and no token persisted' do
    assert_no_difference('PersonalAccessToken.unscoped.count') do
      post :create, params: {
        user_id: @user.id,
        personal_access_token: { name: 'stale-pat' },
      }
    end
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    refute @response.body.include?('token_value')
  end

  test 'create succeeds when fresh' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = @admin.id
    assert_difference('PersonalAccessToken.unscoped.count', 1) do
      post :create, params: {
        user_id: @user.id,
        personal_access_token: { name: 'fresh-pat' },
      }
    end
    assert_response :success
  end

  test 'revoke blocked when stale' do
    token = FactoryBot.create(:personal_access_token, :user => @user)
    refute token.revoked?
    delete :destroy, params: { user_id: @user.id, id: token.id }
    assert_response :forbidden
    refute token.reload.revoked?
  end

  test 'revoke succeeds when fresh' do
    token = FactoryBot.create(:personal_access_token, :user => @user)
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = @admin.id
    delete :destroy, params: { user_id: @user.id, id: token.id }
    assert_response :success
    assert token.reload.revoked?
  end

  test 'setting OFF allows create without recent auth' do
    Setting[:require_reauth_personal_access_tokens_create] = false
    assert_difference('PersonalAccessToken.unscoped.count', 1) do
      post :create, params: {
        user_id: @user.id,
        personal_access_token: { name: 'off-pat' },
      }
    end
    assert_response :success
  end

  test 'machine api session skips interactive reauth gate' do
    @request.session[:api_authenticated_session] = true
    assert_difference('PersonalAccessToken.unscoped.count', 1) do
      post :create, params: {
        user_id: @user.id,
        personal_access_token: { name: 'machine-pat' },
      }
    end
    assert_response :success
  end
end
