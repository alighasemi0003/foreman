# frozen_string_literal: true

require 'test_helper'

class Api::V2::SshKeysControllerReauthenticationTest < ActionController::TestCase
  tests Api::V2::SshKeysController

  valid_attrs = {
    name: 'foreman@example.com',
    key: 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIhRoL6PfBRs9YwW3r2/pYeLrxRzEZSUO3Go8JivxMsguEKjJ3byHDPvPpMHhKKSZD/HJY/A+2Ndqp0ElB+t2qs= foreman@example.com',
  }

  setup do
    @admin = users(:admin)
    @user = FactoryBot.create(:user, :with_mail)
    Setting[:require_reauth_ssh_keys_create] = true
    Setting[:require_reauth_ssh_keys_destroy] = true
    reset_api_credentials
    @request.session[:user] = @admin.id
    @request.session[:expires_at] = 5.minutes.from_now.to_i
    @request.session[:api_authenticated_session] = false
    User.current = @admin
  end

  test 'create blocked when stale and no association' do
    assert_no_difference('SshKey.unscoped.count') do
      post :create, params: { user_id: @user.id, ssh_key: valid_attrs }
    end
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'ssh_keys.create', body.dig('error', 'action')
  end

  test 'create succeeds when fresh' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = @admin.id
    assert_difference('SshKey.unscoped.count', 1) do
      post :create, params: { user_id: @user.id, ssh_key: valid_attrs.merge(name: 'fresh-api') }
    end
    assert_response :created
  end

  test 'create setting OFF allows without recent auth' do
    Setting[:require_reauth_ssh_keys_create] = false
    assert_difference('SshKey.unscoped.count', 1) do
      post :create, params: { user_id: @user.id, ssh_key: valid_attrs.merge(name: 'off-api') }
    end
    assert_response :created
  end

  test 'destroy blocked when stale' do
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    delete :destroy, params: { user_id: @user.id, id: ssh_key.id }
    assert_response :forbidden
    assert SshKey.exists?(ssh_key.id)
  end

  test 'destroy succeeds when fresh' do
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = @admin.id
    delete :destroy, params: { user_id: @user.id, id: ssh_key.id }
    assert_response :success
    refute SshKey.exists?(ssh_key.id)
  end

  test 'machine api credentials skip interactive reauth gate' do
    @request.session[:api_authenticated_session] = true
    assert_difference('SshKey.unscoped.count', 1) do
      post :create, params: { user_id: @user.id, ssh_key: valid_attrs.merge(name: 'machine-api') }
    end
    assert_response :created
  end
end
