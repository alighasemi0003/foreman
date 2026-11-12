# frozen_string_literal: true

require 'test_helper'

class HostsControllerConsoleSecurityTest < ActionController::TestCase
  tests HostsController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_hosts_console] = true
    @host = FactoryBot.create(:host, :managed, :on_compute_resource)
    ComputeResource.any_instance.stubs(:console).returns(
      type: 'vnc',
      name: 'synth-console',
      host: '127.0.0.1',
      port: 5910,
      path: '/?ticket=synth-ticket-hostA',
      password: nil,
      encrypt: false
    )
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  test 'console blocked when reauth stale and password not rendered' do
    get :console, params: { id: @host.to_param }, session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
    refute_includes @response.body.to_s, 'data-password='
    refute_includes @response.body.to_s, 'synthONLY'
  end

  test 'console succeeds without embedding VNC password' do
    get :console, params: { id: @host.to_param }, session: set_session_user(@admin)
    assert_response :success
    assert_match(/no-store/, @response.headers['Cache-Control'].to_s)
    assert_equal 'no-cache', @response.headers['Pragma']
    refute_includes @response.body, 'data-password='
    assert_includes @response.body, 'data-path=\'/?ticket=synth-ticket-hostA\''
    refute_match(/synthONLY|synthVNC|password['\"]?\s*[:=]/i, @response.body)
  end

  test 'unauthorized user cannot open console' do
    setup_user 'view', 'hosts'
    get :console, params: { id: @host.to_param }, session: set_session_user(:one)
    assert_response :forbidden
    refute_includes @response.body.to_s, 'ticket='
  end
end
