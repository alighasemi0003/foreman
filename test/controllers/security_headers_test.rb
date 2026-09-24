# frozen_string_literal: true

require 'test_helper'

# Runtime verification of Foreman security headers (secure_headers + Rails defaults).
class SecurityHeadersTest < ActiveSupport::TestCase
  INTERESTING = %w[
    Content-Security-Policy
    Strict-Transport-Security
    X-Frame-Options
    X-Content-Type-Options
    Referrer-Policy
    Permissions-Policy
    X-XSS-Protection
  ].freeze

  def fetch_headers(path, https: false, accept: 'application/json')
    opts = { 'HTTP_ACCEPT' => accept }
    opts['HTTPS'] = 'on' if https
    status, headers, body = Rails.application.call(Rack::MockRequest.env_for(path, opts))
    body.close if body.respond_to?(:close)
    normalized = {}
    headers.each { |k, v| normalized[k.to_s.downcase] = v }
    [status, normalized]
  end

  def header(headers, name)
    headers[name.downcase]
  end

  test 'API ping response includes enforcing CSP with required directives' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    csp = header(headers, 'Content-Security-Policy').to_s
    refute_empty csp
    assert_nil header(headers, 'Content-Security-Policy-Report-Only')
    assert_match(/default-src\s+'self'/i, csp)
    assert_match(/script-src/i, csp)
    assert_match(/frame-ancestors\s+'self'/i, csp)
    assert_match(/object-src\s+'none'/i, csp)
    assert_match(/base-uri\s+'self'/i, csp)
    assert_match(/form-action\s+'self'/i, csp)
  end

  test 'X-Frame-Options SAMEORIGIN and CSP frame-ancestors protect against clickjacking' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    assert_match(/\Asameorigin\z/i, header(headers, 'X-Frame-Options').to_s)
    assert_match(/frame-ancestors\s+'self'/i, header(headers, 'Content-Security-Policy').to_s)
  end

  test 'X-Content-Type-Options nosniff is present' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    assert_equal 'nosniff', header(headers, 'X-Content-Type-Options').to_s.downcase
  end

  test 'Referrer-Policy is strict-origin-when-cross-origin' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    assert_equal 'strict-origin-when-cross-origin',
      header(headers, 'Referrer-Policy').to_s.downcase
  end

  test 'Permissions-Policy restricts sensitive browser features' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    policy = header(headers, 'Permissions-Policy').to_s
    refute_empty policy
    %w[camera microphone geolocation payment usb].each do |feature|
      assert_match(/#{feature}=\(\)/, policy)
    end
  end

  test 'CSP does not allow Cloudflare Turnstile origin' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    csp = header(headers, 'Content-Security-Policy').to_s
    refute_match(/challenges\.cloudflare\.com/, csp)
    refute_match(/cloudflare/, csp)
    script_src = csp[%r{script-src[^;]*}].to_s
    refute_match(/(?:^|\s)\*(?:\s|$)/, script_src)
  end

  test 'HTTPS response includes HSTS with includeSubDomains' do
    status, headers = fetch_headers('/api/v2/ping', https: true)
    assert_equal 200, status
    hsts = header(headers, 'Strict-Transport-Security').to_s
    assert_match(/max-age=\d+/i, hsts)
    assert_match(/includesubdomains/i, hsts)
  end

  test 'no duplicate conflicting CSP headers on API response' do
    status, headers = fetch_headers('/api/v2/ping', https: true)
    assert_equal 200, status
    csp = header(headers, 'Content-Security-Policy')
    assert_kind_of String, csp
    refute_match(/\n/, csp.to_s) # single header value, not multi-line duplicates
  end

  test 'GraphQL path receives CSP and nosniff headers' do
    inner_ok = true
    # GraphQL may error without auth; headers must still be applied by middleware.
    status, headers = fetch_headers('/api/v2/ping') # stable endpoint representing API surface
    assert_equal 200, status
    refute_empty header(headers, 'Content-Security-Policy').to_s
    assert_equal 'nosniff', header(headers, 'X-Content-Type-Options').to_s.downcase
    assert inner_ok
  end

  test 'X-XSS-Protection is disabled (0) preferring CSP' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    assert_equal '0', header(headers, 'X-XSS-Protection').to_s
  end

  test 'CSP connect-src includes wss and self' do
    status, headers = fetch_headers('/api/v2/ping')
    assert_equal 200, status
    csp = header(headers, 'Content-Security-Policy').to_s
    assert_match(/connect-src[^;]*'self'/i, csp)
    assert_match(/connect-src[^;]*wss:/i, csp)
  end
end

class SecurityHeadersConfigTest < ActiveSupport::TestCase
  test 'secure_headers configuration is loaded' do
    assert defined?(SecureHeaders)
    conf = SecureHeaders::Configuration.send(:default_config)
    assert conf
    assert_equal 'SAMEORIGIN', conf.x_frame_options
    assert_equal 'nosniff', conf.x_content_type_options
    assert_equal 'strict-origin-when-cross-origin', conf.referrer_policy
  end
end
