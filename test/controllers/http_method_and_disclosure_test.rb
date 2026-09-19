# frozen_string_literal: true

require 'test_helper'

class RejectUnsafeHttpMethodsTest < ActiveSupport::TestCase
  def call_app(method, path = '/api/v2/ping')
    opts = {
      'REQUEST_METHOD' => method,
      'HTTP_ACCEPT' => 'application/json',
    }
    status, headers, body = Rails.application.call(Rack::MockRequest.env_for(path, opts))
    body.close if body.respond_to?(:close)
    normalized = {}
    headers.each { |k, v| normalized[k.to_s.downcase] = Array(v).join(',') }
    [status, normalized]
  end

  %w[TRACE TRACK CONNECT PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK FOOBAR].each do |method|
    test "#{method} is rejected with 405 and no business logic" do
      status, headers = call_app(method)
      assert_equal 405, status, "#{method} should be Method Not Allowed"
      assert_match(/GET/, headers['allow'].to_s)
      assert_match(/POST/, headers['allow'].to_s)
      assert_match(/PUT/, headers['allow'].to_s)
      assert_match(/PATCH/, headers['allow'].to_s)
      assert_match(/DELETE/, headers['allow'].to_s)
    end
  end

  test 'GET ping still works' do
    status, = call_app('GET')
    assert_equal 200, status
  end

  test 'HEAD ping still works' do
    status, = call_app('HEAD')
    assert_equal 200, status
  end

  test 'legitimate REST verbs are not blocked by unsafe-method middleware' do
    %w[GET HEAD POST PUT PATCH DELETE OPTIONS].each do |method|
      refute_includes Foreman::Middleware::RejectUnsafeHttpMethods::UNSAFE, method
      assert_includes Foreman::Middleware::RejectUnsafeHttpMethods::ALLOWED, method
    end
  end
end

class ServerDisclosureHeadersTest < ActiveSupport::TestCase
  def fetch(path = '/api/v2/ping')
    status, headers, body = Rails.application.call(
      Rack::MockRequest.env_for(path, 'HTTP_ACCEPT' => 'application/json')
    )
    body.close if body.respond_to?(:close)
    normalized = {}
    headers.each { |k, v| normalized[k.to_s.downcase] = Array(v).join(',') }
    [status, normalized]
  end

  test 'API response does not expose Server or X-Powered-By from Rails/Puma stack' do
    status, headers = fetch
    assert_equal 200, status
    assert_nil headers['server']
    assert_nil headers['x-powered-by']
  end

  test 'API response does not expose X-Runtime timing header' do
    status, headers = fetch
    assert_equal 200, status
    assert_nil headers['x-runtime']
  end

  test 'TRACE response does not echo request or expose server identity' do
    status, headers = call_trace
    assert_equal 405, status
    assert_nil headers['server']
    assert_nil headers['x-powered-by']
    refute_match(/cookie|authorization/i, headers.values.join(' '))
  end

  def call_trace
    status, headers, body = Rails.application.call(
      Rack::MockRequest.env_for('/users/login', 'REQUEST_METHOD' => 'TRACE')
    )
    body.close if body.respond_to?(:close)
    normalized = {}
    headers.each { |k, v| normalized[k.to_s.downcase] = Array(v).join(',') }
    [status, normalized]
  end
end
