# frozen_string_literal: true

require 'test_helper'

class UsersJwtUiHiddenTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:require_reauth_users_terminate_sessions] = false
    @admin = users(:admin)
    @admin.claim_active_session if @admin.respond_to?(:claim_active_session)
    @other = FactoryBot.create(:user, :with_mail, :admin)
    @other.claim_active_session if @other.respond_to?(:claim_active_session)
  end

  test 'users index hides JWT invalidation UI but keeps session terminate controls' do
    get :index, session: set_session_user(@admin)
    assert_response :success
    body = response.body
    assert_includes body, 'Terminate Sessions for all users'
    assert_includes body, 'Terminate Session'
    refute_includes body, 'Invalidate JWTs for all users'
    refute_includes body, 'Invalidate JWTs'
  end
end
