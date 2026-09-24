# frozen_string_literal: true

require 'test_helper'
require 'json'

class ForemanCaptchaTest < ActiveSupport::TestCase
  setup do
    @prev_setting = Setting[:captcha_enabled]
    @prev_settings = SETTINGS[:captcha]
    Setting[:captcha_enabled] = false
    SETTINGS[:captcha] = nil
  end

  teardown do
    Setting[:captcha_enabled] = @prev_setting
    SETTINGS[:captcha] = @prev_settings
  end

  def enable_turnstile_keys!(site: 'test-site-key', secret: 'test-secret-key')
    SETTINGS[:captcha] = {
      provider: 'turnstile',
      turnstile: { site_key: site, secret_key: secret },
    }
  end

  test 'captcha_enabled setting defaults to false' do
    definition = Foreman.settings.find('captcha_enabled')
    assert_not_nil definition
    assert_equal false, definition.default
    assert_equal 'auth', definition.category
  end

  test 'disabled setting verify succeeds without HTTP' do
    Setting[:captcha_enabled] = false
    enable_turnstile_keys!
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('anything')
    assert result.success?
  end

  test 'enabled? follows Setting without restart' do
    enable_turnstile_keys!
    Setting[:captcha_enabled] = false
    refute Foreman::Captcha.enabled?
    assert_equal false, Foreman::Captcha.frontend_config[:enabled]

    Setting[:captcha_enabled] = true
    assert Foreman::Captcha.enabled?
    cfg = Foreman::Captcha.frontend_config
    assert_equal true, cfg[:enabled]
    assert_equal 'test-site-key', cfg[:siteKey]

    Setting[:captcha_enabled] = false
    refute Foreman::Captcha.enabled?
    assert_equal false, Foreman::Captcha.frontend_config[:enabled]
  end

  test 'frontend_config never includes secret' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    cfg = Foreman::Captcha.frontend_config
    assert_equal true, cfg[:enabled]
    assert_equal 'turnstile', cfg[:provider]
    assert_equal 'test-site-key', cfg[:siteKey]
    refute cfg.key?(:secretKey)
    refute cfg.key?(:secret_key)
    refute cfg.values.any? { |v| v.to_s.include?('test-secret-key') }
  end

  test 'enabled with blank token fails closed' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('  ')
    assert result.failed?
    assert_equal :failed, result.status
  end

  test 'enabled with missing site key fails closed' do
    Setting[:captcha_enabled] = true
    SETTINGS[:captcha] = {
      provider: 'turnstile',
      turnstile: { site_key: '', secret_key: 'test-secret-key' },
    }
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('token')
    assert_equal :configuration_error, result.status
    assert Foreman::Captcha.frontend_config[:configurationError]
  end

  test 'enabled with missing secret key fails closed' do
    Setting[:captcha_enabled] = true
    SETTINGS[:captcha] = {
      provider: 'turnstile',
      turnstile: { site_key: 'test-site-key', secret_key: '' },
    }
    Net::HTTP.any_instance.expects(:request).never
    result = Foreman::Captcha.verify('token')
    assert_equal :configuration_error, result.status
  end

  test 'valid turnstile response succeeds' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)
    http_response.stubs(:body).returns({ 'success' => true }.to_json)
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('valid-token', remote_ip: '203.0.113.9')
    assert result.success?
  end

  test 'invalid turnstile response fails' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)
    http_response.stubs(:body).returns({ 'success' => false, 'error-codes' => ['invalid-input-response'] }.to_json)
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('bad-token')
    assert_equal :failed, result.status
  end

  test 'provider HTTP error fails closed' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    http_response = mock('response')
    http_response.stubs(:is_a?).with(Net::HTTPSuccess).returns(false)
    http_response.stubs(:code).returns('500')
    Net::HTTP.any_instance.expects(:request).returns(http_response)

    result = Foreman::Captcha.verify('token')
    assert_equal :provider_error, result.status
  end

  test 'timeout fails closed' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
    Net::HTTP.any_instance.expects(:request).raises(Net::ReadTimeout)

    result = Foreman::Captcha.verify('token')
    assert_equal :provider_error, result.status
  end

  test 'malformed JSON fails closed' do
    Setting[:captcha_enabled] = true
    enable_turnstile_keys!
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
