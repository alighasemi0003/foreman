# frozen_string_literal: true

require 'test_helper'

class Foreman::Middleware::HttpRateLimitTest < ActiveSupport::TestCase
  setup do
    Setting[:http_rate_limit_enabled] = true
    Setting[:http_rate_limit_period] = 60
    Setting[:http_rate_limit_login] = 3
    Setting[:http_rate_limit_api] = 3
    Rails.cache.clear
    @app = ->(_env) { [200, { 'Content-Type' => 'text/plain' }, ['ok']] }
    @middleware = Foreman::Middleware::HttpRateLimit.new(@app)
  end

  teardown do
    Rails.cache.clear
  end

  def env_for(path, method: 'GET', ip: '198.51.100.10', **opts)
    Rack::MockRequest.env_for(path, { method: method, 'REMOTE_ADDR' => ip }.merge(opts))
  end

  test 'passes through under limit' do
    status, = @middleware.call(env_for('/api/v2/hosts', method: 'GET'))
    assert_equal 200, status
  end

  test 'returns 429 with Retry-After when login limit exceeded' do
    3.times { @middleware.call(env_for('/users/login', method: 'POST')) }
    status, headers, body = @middleware.call(env_for('/users/login', method: 'POST'))
    assert_equal 429, status
    assert headers['Retry-After'].present?
    assert_match(/no-store/, headers['Cache-Control'])
    joined = body.join
    refute_match(/password|token|Authorization/i, joined)
    assert_match(/Too many requests/i, joined)
  end

  test 'returns JSON body for API throttle' do
    3.times { @middleware.call(env_for('/api/v2/hosts', method: 'GET')) }
    status, headers, body = @middleware.call(env_for('/api/v2/hosts', method: 'GET'))
    assert_equal 429, status
    assert_match(%r{application/json}, headers['Content-Type'])
    payload = JSON.parse(body.join)
    assert payload.dig('error', 'message').present?
    assert payload.dig('error', 'retry_after').to_i >= 1
  end

  test 'exempt paths are never throttled' do
    20.times do
      status, = @middleware.call(env_for('/api/ping', method: 'GET'))
      assert_equal 200, status
    end
  end

  test 'does not use forged username as identity' do
    # Flood from IP A — body username must not affect the limit key
    3.times do
      @middleware.call(env_for('/users/login', method: 'POST', ip: '198.51.100.1',
        input: 'login=victim&password=x'))
    end
    status_a, = @middleware.call(env_for('/users/login', method: 'POST', ip: '198.51.100.1',
      input: 'login=victim&password=x'))
    assert_equal 429, status_a
    # Different IP still allowed even with same forged username in body
    status_b, = @middleware.call(env_for('/users/login', method: 'POST', ip: '198.51.100.2',
      input: 'login=victim&password=x'))
    assert_equal 200, status_b
  end
end
