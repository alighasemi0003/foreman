# frozen_string_literal: true

require 'test_helper'

class RolesControllerReauthenticationTest < ActionController::TestCase
  tests RolesController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_users_change_roles] = true
    @role = FactoryBot.create(:role, name: "reauth-role-#{Foreman.uuid}")
  end

  test 'role update blocked when stale' do
    original = @role.name
    put :update, params: { id: @role.id, role: { name: "#{original}-x" } },
                 session: { user: @admin.id, expires_at: 5.minutes.from_now }
    assert_response :redirect
    assert_equal original, @role.reload.name
  end

  test 'role update allowed when fresh' do
    original = @role.name
    put :update, params: { id: @role.id, role: { name: "#{original}-y" } },
                 session: set_session_user(@admin)
    assert_response :redirect
    assert_equal "#{original}-y", @role.reload.name
  end

  test 'unauthorized viewer cannot update role even with fresh session' do
    viewer = users(:one)
    original = @role.name
    put :update, params: { id: @role.id, role: { name: "#{original}-z" } },
                 session: set_session_user(viewer)
    assert_response :forbidden
    assert_equal original, @role.reload.name
  end
end
