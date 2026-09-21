# frozen_string_literal: true

require 'test_helper'

class Api::V2::RegistrationCommandsControllerReauthenticationTest < ActionController::TestCase
  tests Api::V2::RegistrationCommandsController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_registration_commands_create] = true
    reset_api_credentials
    @request.session[:user] = @admin.id
    @request.session[:expires_at] = 5.minutes.from_now.to_i
    @request.session[:api_authenticated_session] = false
    User.current = @admin
  end

  test 'create blocked when stale' do
    post :create, params: {}
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'registration_commands.create', body.dig('error', 'action')
  end

  test 'create succeeds when fresh' do
    @request.session[:reauthenticated_at] = Time.now.utc.to_i
    @request.session[:reauth_actor_id] = @admin.id
    post :create, params: {}
    assert_response :success
    assert JSON.parse(@response.body)['registration_command'].present?
  end

  test 'setting OFF allows without recent auth' do
    Setting[:require_reauth_registration_commands_create] = false
    post :create, params: {}
    assert_response :success
  end

  test 'machine api session skips interactive reauth gate' do
    @request.session[:api_authenticated_session] = true
    post :create, params: {}
    assert_response :success
    assert JSON.parse(@response.body)['registration_command'].present?
  end
end
