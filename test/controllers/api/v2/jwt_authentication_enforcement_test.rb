# frozen_string_literal: true

require 'test_helper'

class Api::V2::JwtAuthenticationEnforcementTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    User.current = nil
    @user = as_admin { FactoryBot.create(:user, :admin) }
    @token = @user.jwt_token!
  end

  def auth!(raw)
    @request.headers['Authorization'] = "Bearer #{raw}"
  end

  def get_index
    get :index
  end

  test 'valid JWT authenticates' do
    auth!(@token)
    get_index
    assert_response :success
    assert_equal @user.id, session[:user]
  end

  test 'modified payload returns 401' do
    parts = @token.split('.')
    payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + '=='))
    payload['user_id'] = users(:one).id
    parts[1] = Base64.urlsafe_encode64(payload.to_json, padding: false)
    auth!(parts.join('.'))
    get_index
    assert_response :unauthorized
    assert_nil session[:user]
  end

  test 'modified signature returns 401' do
    parts = @token.split('.')
    parts[2] = "#{parts[2]}x"
    auth!(parts.join('.'))
    get_index
    assert_response :unauthorized
  end

  test 'unsigned alg none returns 401' do
    header = Base64.urlsafe_encode64({ alg: 'none', typ: 'JWT' }.to_json, padding: false)
    body = Base64.urlsafe_encode64({ user_id: @user.id, iat: Time.now.to_i }.to_json, padding: false)
    auth!("#{header}.#{body}.")
    get_index
    assert_response :unauthorized
  end

  test 'unexpected algorithm returns 401' do
    foreign = JWT.encode(
      { 'user_id' => @user.id, 'iat' => Time.now.to_i },
      @user.jwt_secret!.token,
      'HS384'
    )
    auth!(foreign)
    get_index
    assert_response :unauthorized
  end

  test 'token signed with wrong key returns 401' do
    other = as_admin { FactoryBot.create(:user, :admin) }
    bad = JwtToken.encode(@user, other.jwt_secret!.token).to_s
    auth!(bad)
    get_index
    assert_response :unauthorized
  end

  test 'expired JWT returns 401' do
    auth!(@user.jwt_token!(expiration: -30))
    get_index
    assert_response :unauthorized
  end

  test 'invalidated JWT returns 401 and new token works' do
    auth!(@token)
    get_index
    assert_response :success

    @user.invalidate_jwt!
    auth!(@token)
    get_index
    assert_response :unauthorized

    auth!(@user.jwt_token!)
    get_index
    assert_response :success
  end

  test 'other user JWT unaffected by per-user invalidation' do
    other = as_admin { FactoryBot.create(:user, :admin) }
    other_token = other.jwt_token!

    @user.invalidate_jwt!

    auth!(other_token)
    get_index
    assert_response :success
    assert_equal other.id, session[:user]
  end

  test 'invalid JWT does not set privileged session user' do
    auth!('not.a.jwt')
    get_index
    assert_response :unauthorized
    assert_nil session[:user]
    assert_nil User.current
  end
end
