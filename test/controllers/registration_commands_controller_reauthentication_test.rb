# frozen_string_literal: true

require 'test_helper'

class RegistrationCommandsControllerReauthenticationTest < ActionController::TestCase
  tests RegistrationCommandsController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_registration_commands_create] = true
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  test 'create blocked when stale and no command returned' do
    post :create, params: {}, session: stale_session
    if response.redirect?
      assert_match(/Re-authentication required/i, flash[:error].to_s)
    else
      assert_response :forbidden
      body = JSON.parse(@response.body)
      assert body.dig('error', 'reauthentication_required')
    end
  end

  test 'create succeeds when fresh' do
    post :create, params: {}, session: set_session_user(@admin)
    assert_response :success
    body = JSON.parse(@response.body)
    assert body['command'].present?
    assert_includes body['command'], 'Bearer '
  end

  test 'setting OFF allows create without recent auth' do
    Setting[:require_reauth_registration_commands_create] = false
    post :create, params: {}, session: stale_session
    assert_response :success
    assert JSON.parse(@response.body)['command'].present?
  end
end
