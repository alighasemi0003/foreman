# frozen_string_literal: true

require 'test_helper'

class ForemanCaptchaTest < ActiveSupport::TestCase
  setup do
    @prev_setting = Setting[:captcha_enabled]
    @prev_ttl = SETTINGS.dig(:captcha, :ttl_seconds)
    Setting[:captcha_enabled] = false
    SETTINGS[:captcha] = nil
    @session = {}
  end

  teardown do
    Setting[:captcha_enabled] = @prev_setting
    SETTINGS[:captcha] = @prev_ttl.nil? ? nil : { ttl_seconds: @prev_ttl }
  end

  test 'captcha_enabled setting defaults to false' do
    definition = Foreman.settings.find('captcha_enabled')
    assert_not_nil definition
    assert_equal false, definition.default
    assert_equal 'auth', definition.category
  end

  test 'disabled captcha verify succeeds without session challenge' do
    Setting[:captcha_enabled] = false
    result = Foreman::Captcha.verify('anything', session: @session)
    assert result.success?
  end

  test 'enabled? follows Setting without restart' do
    Setting[:captcha_enabled] = false
    refute Foreman::Captcha.enabled?
    assert_equal false, Foreman::Captcha.frontend_config(@session)[:enabled]

    Setting[:captcha_enabled] = true
    assert Foreman::Captcha.enabled?
    cfg = Foreman::Captcha.frontend_config(@session)
    assert_equal true, cfg[:enabled]
    assert_equal 'local', cfg[:provider]
    assert cfg[:question].present?
    refute cfg.key?(:answer)
    refute cfg.key?(:digest)

    Setting[:captcha_enabled] = false
    refute Foreman::Captcha.enabled?
  end

  test 'frontend_config never exposes answer' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(12, 34)
    cfg = Foreman::Captcha.frontend_config(@session)
    assert_match(/12.*\+.*34|What is/, cfg[:question])
    refute_includes cfg[:question], '46' if cfg[:question] !~ /\+/
    stored = @session[Foreman::Captcha::Local::SESSION_KEY]
    assert stored['digest'].present?
    refute_equal '46', stored['digest']
    refute cfg.values.any? { |v| v.to_s == '46' }
  end

  test 'issue uses SecureRandom not Kernel rand' do
    Setting[:captcha_enabled] = true
    Kernel.expects(:rand).never
    SecureRandom.expects(:random_number).with(10..40).returns(11)
    SecureRandom.expects(:random_number).with(10..40).returns(12)
    Foreman::Captcha::Local.issue!(@session)
    assert_equal Foreman::Captcha::Local.digest('23'),
      @session[Foreman::Captcha::Local::SESSION_KEY]['digest']
  end

  test 'valid answer succeeds and consumes challenge' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(10, 15)
    Foreman::Captcha::Local.issue!(@session)
    result = Foreman::Captcha.verify('25', session: @session)
    assert result.success?
    assert_nil @session[Foreman::Captcha::Local::SESSION_KEY]
  end

  test 'wrong answer fails and consumes challenge' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(10, 15)
    Foreman::Captcha::Local.issue!(@session)
    result = Foreman::Captcha.verify('99', session: @session)
    assert_equal :failed, result.status
    assert_nil @session[Foreman::Captcha::Local::SESSION_KEY]
  end

  test 'missing answer fails' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(1, 2)
    Foreman::Captcha::Local.issue!(@session)
    result = Foreman::Captcha.verify('  ', session: @session)
    assert result.failed?
  end

  test 'expired challenge fails' do
    Setting[:captcha_enabled] = true
    SETTINGS[:captcha] = { ttl_seconds: 60 }
    SecureRandom.stubs(:random_number).returns(3, 4)
    Foreman::Captcha::Local.issue!(@session)
    @session[Foreman::Captcha::Local::SESSION_KEY]['created_at'] = 10.minutes.ago.to_i
    result = Foreman::Captcha.verify('7', session: @session)
    assert_equal :failed, result.status
    assert_equal 'captcha_expired', result.message
  end

  test 'reused challenge fails' do
    Setting[:captcha_enabled] = true
    SecureRandom.stubs(:random_number).returns(8, 9)
    Foreman::Captcha::Local.issue!(@session)
    assert Foreman::Captcha.verify('17', session: @session).success?
    reused = Foreman::Captcha.verify('17', session: @session)
    assert reused.failed?
    assert_equal 'captcha_missing', reused.message
  end

  test 'provider is local' do
    assert_equal 'local', Foreman::Captcha.provider
  end
end
