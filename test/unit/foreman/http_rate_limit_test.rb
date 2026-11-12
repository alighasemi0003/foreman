# frozen_string_literal: true

require 'test_helper'

class Foreman::HttpRateLimitTest < ActiveSupport::TestCase
  setup do
    Setting[:http_rate_limit_enabled] = true
    Setting[:http_rate_limit_period] = 60
    Setting[:http_rate_limit_login] = 5
    Setting[:http_rate_limit_api] = 10
    Setting[:http_rate_limit_captcha] = 5
    Setting[:http_rate_limit_graphql] = 5
    Setting[:http_rate_limit_unattended] = 5
    Setting[:http_rate_limit_general] = 10
    Setting[:http_rate_limit_fail_closed] = false
    Rails.cache.clear
  end

  teardown do
    Setting[:http_rate_limit_enabled] = true
    Setting[:http_rate_limit_fail_closed] = false
    Rails.cache.clear
  end

  test 'classifies login captcha api graphql unattended and exempt paths' do
    assert_equal :login, Foreman::HttpRateLimit.classify('/users/login', 'POST')
    assert_equal :general, Foreman::HttpRateLimit.classify('/users/login', 'GET')
    assert_equal :captcha, Foreman::HttpRateLimit.classify('/users/captcha_challenge', 'GET')
    assert_equal :graphql, Foreman::HttpRateLimit.classify('/api/graphql', 'POST')
    assert_equal :api, Foreman::HttpRateLimit.classify('/api/v2/hosts', 'GET')
    assert_equal :unattended, Foreman::HttpRateLimit.classify('/unattended/provision', 'GET')
    assert_equal :exempt, Foreman::HttpRateLimit.classify('/api/ping', 'GET')
    assert_equal :exempt, Foreman::HttpRateLimit.classify('/assets/application.js', 'GET')
    assert_equal :exempt, Foreman::HttpRateLimit.classify('/status', 'GET')
  end

  test 'allows requests under the limit' do
    5.times do
      result = Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.10')
      assert result.allowed, "expected allow count=#{result.count}"
    end
  end

  test 'rejects requests over the limit with retry_after' do
    5.times { Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.11') }
    result = Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.11')
    refute result.allowed
    assert_operator result.retry_after, :>=, 1
    assert_equal 5, result.limit
  end

  test 'isolates clients by IP' do
    5.times { Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.20') }
    denied = Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.20')
    refute denied.allowed
    other = Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.21')
    assert other.allowed
  end

  test 'isolates categories' do
    5.times { Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.30') }
    refute Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.30').allowed
    assert Foreman::HttpRateLimit.check!(category: :api, client_ip: '203.0.113.30').allowed
  end

  test 'disabled limiter always allows' do
    Setting[:http_rate_limit_enabled] = false
    20.times do
      assert Foreman::HttpRateLimit.check!(category: :login, client_ip: '203.0.113.40').allowed
    end
  end

  test 'fail open when cache raises and fail_closed is false' do
    Rails.cache.stubs(:increment).raises(RuntimeError.new('cache down'))
    result = Foreman::HttpRateLimit.check!(category: :api, client_ip: '203.0.113.50')
    assert result.allowed
    assert_equal :store_unavailable, result.error
  end

  test 'fail closed when cache raises and fail_closed is true' do
    Setting[:http_rate_limit_fail_closed] = true
    Rails.cache.stubs(:increment).raises(RuntimeError.new('cache down'))
    result = Foreman::HttpRateLimit.check!(category: :api, client_ip: '203.0.113.51')
    refute result.allowed
    assert_equal :store_unavailable, result.error
  end
end
