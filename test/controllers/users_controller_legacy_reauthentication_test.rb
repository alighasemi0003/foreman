# frozen_string_literal: true

require 'test_helper'

class LegacyHtmlReauthenticationResponseTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    @admin.update_column(:has_active_session, true)
    @target = FactoryBot.create(:user, :with_mail)
    Setting[:require_reauth_users_destroy] = true
    Setting[:require_reauth_users_impersonate] = true
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  test 'HTML destroy without accept header uses flash redirect (no-JS fallback)' do
    assert_no_difference('User.unscoped.count') do
      delete :destroy, params: { id: @target.id }, session: stale_session
    end
    assert_response :redirect
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'destroy with X-Foreman-Accept-Reauth returns structured JSON 403' do
    @request.headers['X-Foreman-Accept-Reauth'] = '1'
    assert_no_difference('User.unscoped.count') do
      delete :destroy, params: { id: @target.id }, session: stale_session
    end
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'users.destroy', body.dig('error', 'action')
    assert body.dig('error').key?('reauthentication_supported')
    assert_nil flash[:error]
  end

  test 'impersonate with accept header returns structured JSON when stale' do
    @request.headers['X-Foreman-Accept-Reauth'] = '1'
    post :impersonate, params: { id: @target.id }, session: stale_session
    assert_response :forbidden
    body = JSON.parse(@response.body)
    assert body.dig('error', 'reauthentication_required')
    assert_equal 'users.impersonate', body.dig('error', 'action')
  end

  test 'unauthorized destroy with accept header does not claim reauth required' do
    viewer = users(:one)
    viewer.update_column(:has_active_session, true)
    @request.headers['X-Foreman-Accept-Reauth'] = '1'
    delete :destroy, params: { id: @target.id },
                     session: set_session_user(viewer)
    assert_includes [403, 404], response.status
    assert User.unscoped.exists?(@target.id)
    if response.media_type&.include?('json')
      body = JSON.parse(@response.body) rescue {}
      refute body.dig('error', 'reauthentication_required')
    end
  end
end
