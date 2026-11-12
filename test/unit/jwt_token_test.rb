require 'test_helper'
require 'ostruct'

class JwtTokenTest < ActiveSupport::TestCase
  # Token created from encoding with 'test_jwt_secret' a following payload:
  # { 'user_id' => 123, 'iat' => 1514804400, 'jti' => '3e8286940eb162ec735f8a5aac5926037fdc7f05e521a74231a65f2557a8af94' }
  let(:token) { 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjMsImlhdCI6MTUxNDgwNDQwMCwianRpIjoiM2U4Mjg2OTQwZWIxNjJlYzczNWY4YTVhYWM1OTI2MDM3ZmRjN2YwNWU1MjFhNzQyMzFhNjVmMjU1N2E4YWY5NCJ9.TSM2xMnMuMEWwAVoIidyLIwJElJQZVQvcfaxyVA7cDI' }

  test 'encoding' do
    JwtToken.stubs(:iat).returns(1_514_804_400)

    user = OpenStruct.new(id: 123)
    jwt_token = JwtToken.encode(user, 'test_jwt_secret')

    assert_equal token, jwt_token.to_s
  end

  test 'encode with expiration' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret')
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    user = OpenStruct.new(id: 123)
    jwt_token = JwtToken.new(JwtToken.encode(user, jwt_secret.token, expiration: 3600).token)

    assert_nothing_raised { jwt_token.decode }
  end

  test 'encode with scope' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret')
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    scope = [{ controller: 'hosts', actions: ['create', 'update']}]
    jwt_token = JwtToken.new(JwtToken.encode(OpenStruct.new(id: 123), jwt_secret.token, scope: scope).token)

    assert_equal 'hosts#create hosts#update', jwt_token.decode['scope']
  end

  test 'decoding' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret')
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    jwt_token = JwtToken.new(token)

    expected = {'user_id' => 123,
                'iat' => 1_514_804_400,
                'jti' => '3e8286940eb162ec735f8a5aac5926037fdc7f05e521a74231a65f2557a8af94'}

    assert_equal expected, jwt_token.decode
  end

  test 'decoding invalid token' do
    jwt_token = JwtToken.new('inVaLiD.inVaLiD.inVaLiD')

    assert_nil jwt_token.decode
  end

  test 'decoding a nil token' do
    jwt_token = JwtToken.new(nil)

    assert_nil jwt_token.decode
  end

  test 'decoding empty token' do
    jwt_token = JwtToken.new('')

    assert_nil jwt_token.decode
  end

  test 'decoding garbage token' do
    jwt_token = JwtToken.new('fjdfhjjkdsjfdjksn')

    assert_nil jwt_token.decode
  end

  test 'decoding with invalid secret' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'invalid_jwt_secret')
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    jwt_token = JwtToken.new(token)

    assert_nil jwt_token.decode
  end

  test 'decoding expired token' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret')
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    user = OpenStruct.new(id: 123)
    jwt_token = JwtToken.new(JwtToken.encode(user, jwt_secret.token, expiration: -1).token)

    assert_nil jwt_token.decode
  end

  test 'decoded_payload is inspection-only and does not authenticate tampered tokens' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret', user_id: 123)
    JwtSecret.stubs(:find_by).with(user_id: 123).returns(jwt_secret)

    # Forge unsigned / alg:none token claiming user_id 123
    header = Base64.urlsafe_encode64({ alg: 'none', typ: 'JWT' }.to_json, padding: false)
    body = Base64.urlsafe_encode64({ user_id: 123, iat: Time.now.to_i }.to_json, padding: false)
    none_token = "#{header}.#{body}."

    jwt = JwtToken.new(none_token)
    assert_equal 123, jwt.decoded_payload['user_id']
    assert_nil jwt.decode, 'alg:none must not verify'
  end

  test 'tampered payload fails verification' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret', user_id: 123)
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    raw = JwtToken.encode(OpenStruct.new(id: 123), jwt_secret.token).to_s
    parts = raw.split('.')
    payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + '=='))
    payload['user_id'] = 999
    parts[1] = Base64.urlsafe_encode64(payload.to_json, padding: false)
    tampered = parts.join('.')

    jwt = JwtToken.new(tampered)
    # Inspection may still show forged user_id; verified decode must fail.
    assert_nil jwt.decode
  end

  test 'unexpected algorithm fails verification' do
    jwt_secret = FactoryBot.build(:jwt_secret, token: 'test_jwt_secret', user_id: 123)
    JwtSecret.stubs(:find_by).returns(jwt_secret)
    foreign = JWT.encode({ 'user_id' => 123, 'iat' => Time.now.to_i }, jwt_secret.token, 'HS384')
    assert_nil JwtToken.new(foreign).decode
  end

  test 'encode uses HS256' do
    raw = JwtToken.encode(OpenStruct.new(id: 1), 'abc').to_s
    header = JSON.parse(Base64.urlsafe_decode64(raw.split('.').first + '=='))
    assert_equal 'HS256', header['alg']
  end
end
