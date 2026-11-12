# frozen_string_literal: true

require 'test_helper'
require 'active_record/session_store/session'
require 'foreman/session_cookie_encryptor'

class EncryptedSessionCookieStoreIntegrationTest < ActiveSupport::TestCase
  setup do
    Foreman::SessionCookieEncryptor.reset_encryptor!
  end

  teardown do
    Foreman::SessionCookieEncryptor.reset_encryptor!
  end

  def call_app(cookie: nil)
    env_opts = { 'HTTP_ACCEPT' => 'application/json' }
    env_opts['HTTP_COOKIE'] = "_session_id=#{cookie}" if cookie
    env = Rack::MockRequest.env_for('/api/v2/ping', env_opts)
    status, headers, body = Rails.application.call(env)
    body.close if body.respond_to?(:close)
    [status, headers]
  end

  def set_cookie_value(headers)
    raw = headers['Set-Cookie'].to_s
    line = raw.split("\n").find { |c| c.start_with?('_session_id=') }
    assert_not_nil line
    CGI.unescape(line.split(';', 2).first.split('=', 2).last)
  end

  test 'valid encrypted cookie authenticates to same server session row' do
    status, headers = call_app
    assert_equal 200, status
    sealed = set_cookie_value(headers)
    public_id = Foreman::SessionCookieEncryptor.decrypt(sealed)
    assert public_id.present?
    private_id = Rack::Session::SessionId.new(public_id).private_id
    assert ActiveRecord::SessionStore::Session.find_by_session_id(private_id)

    status2, = call_app(cookie: sealed)
    assert_equal 200, status2
  end

  test 'tampered cookie is rejected and issues a new encrypted cookie' do
    _, headers = call_app
    sealed = set_cookie_value(headers)
    tampered = sealed.sub(/.\z/, sealed[-1] == 'A' ? 'B' : 'A')
    status, headers2 = call_app(cookie: tampered)
    assert_equal 200, status
    new_sealed = set_cookie_value(headers2)
    assert Foreman::SessionCookieEncryptor.encrypted?(new_sealed)
    refute_equal sealed, new_sealed
  end

  test 'legacy plaintext sid cookie is rejected' do
    legacy = SecureRandom.hex(16)
    status, headers = call_app(cookie: legacy)
    assert_equal 200, status
    sealed = set_cookie_value(headers)
    assert Foreman::SessionCookieEncryptor.encrypted?(sealed)
    refute_equal legacy, Foreman::SessionCookieEncryptor.decrypt(sealed)
  end
end
