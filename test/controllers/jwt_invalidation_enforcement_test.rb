# frozen_string_literal: true

require 'test_helper'

class JwtInvalidationEnforcementTest < ActionController::TestCase
  tests UsersController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_users_invalidate_jwt] = false
    User.current = @admin
  end

  def issue_token_for(user)
    user.jwt_token!
  end

  def token_authenticates?(raw_token)
    JwtToken.new(raw_token).decode.present?
  end

  test 'existing JWT valid before per-user invalidation and rejected after' do
    user = FactoryBot.create(:user, :with_mail)
    other = FactoryBot.create(:user, :with_mail)
    token = issue_token_for(user)
    other_token = issue_token_for(other)

    assert token_authenticates?(token)
    assert token_authenticates?(other_token)

    patch :invalidate_jwt, params: { id: user.id }, session: set_session_user(@admin)
    assert_response :redirect

    user.reload
    assert_nil user.jwt_secret
    refute token_authenticates?(token), 'previously issued JWT must fail after invalidate'
    assert token_authenticates?(other_token), 'other user JWT must remain valid'

    new_token = issue_token_for(user)
    assert token_authenticates?(new_token)
    refute token_authenticates?(token)
  end

  test 'global invalidation rejects existing JWTs for multiple users' do
    users = Array.new(2) { FactoryBot.create(:user, :with_mail) }
    tokens = users.map { |u| issue_token_for(u) }
    tokens.each { |t| assert token_authenticates?(t) }

    delete :invalidate_jwt_for_all_users, session: set_session_user(@admin)
    assert_response :redirect

    tokens.each { |t| refute token_authenticates?(t) }
    users.each do |u|
      u.reload
      assert_nil u.jwt_secret
      assert token_authenticates?(issue_token_for(u))
    end
  end

  test 'unauthorized actor cannot invalidate another users JWTs' do
    actor = users(:one)
    target = users(:two)
    token = issue_token_for(target)

    patch :invalidate_jwt, params: { id: target.id }, session: set_session_user(actor)
    assert_response :forbidden
    assert token_authenticates?(token)
    assert_not_nil target.reload.jwt_secret
  end

  test 'GET is not routed for JWT invalidation' do
    user = FactoryBot.create(:user, :with_mail)
    token = issue_token_for(user)
    assert_raises(ActionController::RoutingError) do
      Rails.application.routes.recognize_path(
        "/users/#{user.id}/invalidate_jwt", method: :get
      )
    end
    assert token_authenticates?(token)
  end

  test 'stale session reauth blocks invalidate until fresh' do
    Setting[:require_reauth_users_invalidate_jwt] = true
    user = FactoryBot.create(:user, :with_mail)
    token = issue_token_for(user)
    stale = { user: @admin.id, expires_at: 5.minutes.from_now }

    patch :invalidate_jwt, params: { id: user.id }, session: stale
    assert token_authenticates?(token), 'JWT must remain valid when invalidate is blocked by reauth'

    patch :invalidate_jwt, params: { id: user.id }, session: set_session_user(@admin)
    refute token_authenticates?(token)
  end

  test 'jwt_secret! recreates after invalidate without association stuck on destroyed record' do
    user = FactoryBot.create(:user, :with_mail)
    old = issue_token_for(user)
    user.invalidate_jwt!
    refute token_authenticates?(old)
    new_token = user.jwt_token!
    assert token_authenticates?(new_token)
    assert user.jwt_secret.persisted?
  end
end
