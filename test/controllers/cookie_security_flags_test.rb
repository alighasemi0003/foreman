# frozen_string_literal: true

require 'test_helper'

# Runtime Set-Cookie verification for Secure / HttpOnly / SameSite on session cookies.
class CookieSecurityFlagsTest < ActiveSupport::TestCase
  setup do
    @previous_secure = Rails.application.config.session_options[:secure]
    @previous_always_write = ActionDispatch::Cookies::CookieJar.always_write_cookie
  end

  teardown do
    Rails.application.config.session_options[:secure] = @previous_secure
    ActionDispatch::Cookies::CookieJar.always_write_cookie = @previous_always_write
  end

  def ping_set_cookie(https: false, secure_option: nil)
    unless secure_option.nil?
      Rails.application.config.session_options[:secure] = secure_option
      ActionDispatch::Cookies::CookieJar.always_write_cookie = true if secure_option
    end

    env_opts = { 'HTTP_ACCEPT' => 'application/json' }
    env_opts['HTTPS'] = 'on' if https
    env = Rack::MockRequest.env_for('/api/v2/ping', env_opts)
    status, headers, body = Rails.application.call(env)
    body.close if body.respond_to?(:close)
    assert_equal 200, status

    raw = headers['Set-Cookie'].to_s
    line = raw.split("\n").find { |c| c.start_with?('_session_id=') }
    assert_not_nil line, "Expected _session_id Set-Cookie (redacted dump): #{raw.gsub(/=[^;]*/, '=[REDACTED]')}"
    line
  end

  test 'session store configures Secure from require_ssl and explicit HttpOnly' do
    opts = Rails.application.config.session_options
    assert_equal '_session_id', opts[:key]
    assert_equal !!SETTINGS[:require_ssl], opts[:secure]
    assert_equal true, opts[:httponly]
  end

  test 'session cookie Set-Cookie includes HttpOnly' do
    header = ping_set_cookie
    assert_match(/;\s*HttpOnly(?:;|$|\s)/i, header)
  end

  test 'session cookie Set-Cookie includes SameSite=Lax' do
    header = ping_set_cookie
    assert_match(/;\s*SameSite=Lax(?:;|$|\s)/i, header)
  end

  test 'session cookie Set-Cookie includes Secure when secure session option enabled' do
    header = ping_set_cookie(https: true, secure_option: true)
    assert_match(/;\s*secure(?:;|$|\s)/i, header)
  end

  test 'session cookie Set-Cookie includes Path=/' do
    header = ping_set_cookie
    assert_match(/;\s*path=\//i, header)
  end

  test 'session cookie value is opaque sid without embedded auth secrets' do
    header = ping_set_cookie
    value = header.split(';', 2).first.split('=', 2).last
    refute_match(/password|token|bearer|jwt/i, value)
    refute_match(/\AeyJ/, value)
  end

  test 'no SameSite=None cookie is issued without Secure on ping' do
    header = ping_set_cookie
    if header.match?(/SameSite=None/i)
      assert_match(/;\s*secure(?:;|$|\s)/i, header)
    end
  end
end

class CookieSecuritySessionLifecycleTest < ActionController::TestCase
  tests UsersController

  test 'login still establishes a session with CSRF verification stubbed' do
    @controller.stubs(:verify_authenticity_token).returns(true)
    post :login, params: { :login => { :login => users(:admin).login, :password => 'changeme' } }
    assert_includes [200, 302], response.status
  end

  test 'logout still works with session' do
    @controller.stubs(:verify_authenticity_token).returns(true)
    post :logout, session: set_session_user
    assert_includes [200, 302], response.status
  end
end

class CookieSecurityTimezoneNotAuthTest < ActiveSupport::TestCase
  test 'timezone cookie is UX-only with SameSite Lax and conditional Secure' do
    source = File.read(Rails.root.join('webpack/assets/javascripts/react_app/common/I18n.js'))
    assert_match(/Cookies\.set\('timezone'/, source)
    assert_match(/sameSite:\s*'Lax'/, source)
    assert_match(/secure:\s*window\.location\.protocol === 'https:'/, source)
  end
end
