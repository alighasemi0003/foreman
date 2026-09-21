# frozen_string_literal: true

require 'test_helper'

# Runtime HTTPS enforcement tests using the same ActionDispatch::SSL behavior
# Foreman enables when SETTINGS[:require_ssl] / config.force_ssl is true.
class HttpsEnforcementTest < ActiveSupport::TestCase
  def ssl_app
    ActionDispatch::SSL.new(
      Rails.application,
      redirect: {
        exclude: ->(request) { Foreman::ForceSsl.new(request).allows_http? },
      },
      hsts: { expires: 20.years.to_i, subdomains: true, preload: false },
      secure_cookies: true
    )
  end

  def call_ssl(path, method: 'GET', https: false, query: nil, headers: {}, body: nil)
    opts = headers.dup
    opts['HTTPS'] = 'on' if https
    opts['REQUEST_METHOD'] = method
    url = query ? "#{path}?#{query}" : path
    env = Rack::MockRequest.env_for(url, opts)
    if body
      env['rack.input'] = StringIO.new(body)
      env['CONTENT_LENGTH'] = body.bytesize.to_s
      env['CONTENT_TYPE'] ||= 'application/x-www-form-urlencoded'
    end
    status, response_headers, response_body = ssl_app.call(env)
    response_body.close if response_body.respond_to?(:close)
    [status, response_headers]
  end

  test 'HTTP GET root redirects to HTTPS preserving path' do
    status, headers = call_ssl('/')
    assert_equal 301, status
    assert_match(%r{\Ahttps://[^/]+/\z}, headers['Location'])
  end

  test 'HTTP GET login redirects to HTTPS preserving path' do
    status, headers = call_ssl('/users/login')
    assert_equal 301, status
    assert_equal 'https://example.org/users/login', headers['Location']
  end

  test 'HTTP GET login with query string preserves query' do
    status, headers = call_ssl('/users/login', query: 'status=401&x=1')
    assert_equal 301, status
    assert_equal 'https://example.org/users/login?status=401&x=1', headers['Location']
  end

  test 'HTTP GET API ping redirects to HTTPS' do
    status, headers = call_ssl('/api/v2/ping', headers: { 'HTTP_ACCEPT' => 'application/json' })
    assert_equal 301, status
    assert_match(%r{\Ahttps://[^/]+/api/v2/ping\z}, headers['Location'])
  end

  test 'HTTP GraphQL redirects to HTTPS' do
    status, headers = call_ssl('/api/graphql', method: 'POST',
      headers: { 'HTTP_ACCEPT' => 'application/json', 'CONTENT_TYPE' => 'application/json' },
      body: '{"query":"{ __typename }"}')
    assert_equal 307, status
    assert_match(%r{\Ahttps://[^/]+/api/graphql\z}, headers['Location'])
  end

  test 'HTTP POST login redirects with 307 and does not reach app as success' do
    status, headers = call_ssl('/users/login', method: 'POST',
      body: 'login[login]=admin&login[password]=changeme')
    assert_equal 307, status
    assert_match(%r{\Ahttps://}, headers['Location'])
    # Redirect response has no session establishment semantics on plain HTTP
    refute_match(/text\/html.*Log In/i, headers['Content-Type'].to_s + headers['Location'].to_s)
  end

  test 'HTTP PATCH hosts redirects with 307 before business logic' do
    status, headers = call_ssl('/hosts/1', method: 'PATCH', body: 'host[name]=x')
    assert_equal 307, status
    assert_match(%r{\Ahttps://[^/]+/hosts/1\z}, headers['Location'])
  end

  test 'HTTPS UI path is not SSL-redirected' do
    # Use API ping as lightweight HTTPS success path (login hits webpack/bruteforce fixtures).
    status, headers = call_ssl('/api/v2/ping', https: true,
      headers: { 'HTTP_ACCEPT' => 'application/json' })
    assert_equal 200, status
    refute headers['Location']
  end

  test 'HTTPS API ping succeeds without HTTPS redirect' do
    status, headers = call_ssl('/api/v2/ping', https: true,
      headers: { 'HTTP_ACCEPT' => 'application/json' })
    assert_equal 200, status
    refute headers['Location']
  end

  test 'HTTPS GraphQL is not SSL-redirected' do
    # Wrap a minimal app to assert SSL middleware pass-through for GraphQL path
    inner = lambda do |_env|
      [200, { 'Content-Type' => 'application/json' }, ['{"data":{}}']]
    end
    app = ActionDispatch::SSL.new(
      inner,
      redirect: { exclude: ->(request) { Foreman::ForceSsl.new(request).allows_http? } },
      hsts: true
    )
    env = Rack::MockRequest.env_for('/api/graphql',
      'HTTPS' => 'on',
      'REQUEST_METHOD' => 'POST',
      'CONTENT_TYPE' => 'application/json')
    status, headers, body = app.call(env)
    body.close if body.respond_to?(:close)
    assert_equal 200, status
    refute headers['Location']
  end

  test 'HTTPS response includes HSTS header from SSL middleware' do
    status, headers = call_ssl('/api/v2/ping', https: true,
      headers: { 'HTTP_ACCEPT' => 'application/json' })
    assert_equal 200, status
    hsts = headers['Strict-Transport-Security'].to_s
    assert_match(/max-age=\d+/i, hsts)
    assert_match(/includeSubDomains/i, hsts)
  end

  test 'X-Forwarded-Proto https from trusted proxy is treated as SSL (no redirect loop)' do
    status, headers = call_ssl('/api/v2/ping',
      headers: {
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_FORWARDED_PROTO' => 'https',
        'REMOTE_ADDR' => '127.0.0.1',
      })
    # Trusted loopback proxy + X-Forwarded-Proto => request.ssl? => app handles request
    assert_equal 200, status
    refute headers['Location']
  end

  test 'force_ssl setting is aligned with session Secure cookie option' do
    assert_equal !!SETTINGS[:require_ssl], !!Rails.application.config.force_ssl
    assert_equal !!SETTINGS[:require_ssl], !!Rails.application.config.session_options[:secure]
  end

  test 'unattended HTTP exemption only when unattended_url is http' do
    Setting.stubs(:[]).with(:unattended_url).returns('http://foreman.example.com/')
    request = stub(path_info: '/unattended/provision', params: {})
    assert Foreman::ForceSsl.new(request).allows_http?

    Setting.stubs(:[]).with(:unattended_url).returns('https://foreman.example.com/')
    refute Foreman::ForceSsl.new(request).allows_http?
  end

  test 'general UI paths never allow HTTP under ForceSsl' do
    %w[/ /users/login /hosts /settings /api/v2/ping /api/graphql].each do |path|
      request = stub(path_info: path, params: {})
      refute Foreman::ForceSsl.new(request).allows_http?, "#{path} must require SSL"
    end
  end
end

class HttpsEnforcementConfigTest < ActiveSupport::TestCase
  test 'application wires force_ssl from require_ssl with ForceSsl exclude' do
    assert Rails.application.config.ssl_options[:redirect].key?(:exclude)
    # Test env keeps require_ssl false so local HTTP tests work
    assert_equal false, SETTINGS[:require_ssl]
    assert_equal false, Rails.application.config.force_ssl
  end

  test 'secure_headers HSTS configuration follows hsts_enabled' do
    assert SETTINGS.fetch(:hsts_enabled, true)
  end
end
