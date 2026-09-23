# frozen_string_literal: true

require 'test_helper'
require 'json'

class ForemanCaptchaTest < ActiveSupport::TestCase
  setup do
    @prev = SETTINGS[:captcha]
  end

  teardown do
    SETTINGS[:captcha] = @prev
  end

  def enable_turnstile!(site: 'test-site-key', secret: 'test-secret-key')
    SETTINGS[:captcha] = {
      enabled: true,
      provider: 'turnstile',
      turnstile: { site_key: site, secret_key: secret },
    }
  end

  test 'disabled captcha verify succeeds without HTTP' do
    SETTINGS[:captcha] = { enabled: false }
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('anything')
    assert result.success?
  end

  test 'frontend_config never includes secret' do
    enable_turnstile!
    cfg = Foreman::Captcha.frontend_config
    assert_equal true, cfg[:enabled]
    assert_equal 'turnstile', cfg[:provider]
    assert_equal 'test-site-key', cfg[:siteKey]
    refute cfg.key?(:secretKey)
    refute cfg.key?(:secret_key)
    refute cfg.values.any? { |v| v.to_s.include?('test-secret-key') }
  end

  test 'enabled with blank token fails closed' do
    enable_turnstile!
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('  ')
    assert result.failed?
    assert_equal :failed, result.status
  end

  test 'enabled with missing configuration fails closed' do
    SETTINGS[:captcha] = { enabled: true, provider: 'turnstile', turnstile: { site_key: '', secret_key: '' } }
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('token')
    assert_equal :configuration_error, result.status
  end

  test 'valid turnstile response succeeds' do
    enable_turnstile!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)
    http_response.stubs(:body).returns({ 'success' => true }.to_json)
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('valid-token', remote_ip: '203.0.113.9')
    assert result.success?
  end

  test 'invalid turnstile response fails' do
    enable_turnstile!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)
    http_response.stubs(:body).returns({ 'success' => false, 'error-codes' => ['invalid-input-response'] }.to_json)
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('bad-token')
    assert_equal :failed, result.status
  end

  test 'provider HTTP error fails closed' do
    enable_turnstile!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(false)
    http_response.stubs(:code).returns('500')
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('token')
    assert_equal :provider_error, result.status
  end

  test 'timeout fails closed' do
    enable_turnstile!
    Net::HTTP.any_instance.expects(:request).raises(Net::ReadTimeout)

    result = Foreman::Captcha.verify('token')
    assert_equal :provider_error, result.status
  end

  test 'malformed JSON fails closed' do
    enable_turnstile!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)
    http_response.stubs(:body).returns('not-json')
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('token')
    assert_equal :provider_error, result.status
  end

  test 'siteverify URL is fixed Cloudflare endpoint' do
    assert_equal 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      Foreman::Captcha::TURNSTILE_SITEVERIFY_URL
  end
end
