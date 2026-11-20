# frozen_string_literal: true

require 'test_helper'

class Foreman::SecureDefaultsTest < ActiveSupport::TestCase
  setup do
    @prev_baseline = Setting[:security_hardening_baseline]
    @prev_captcha = Setting[:captcha_enabled]
    @prev_age = Setting[:password_max_age]
    @prev_idle = Setting[:idle_timeout]
    @prev_fail = Setting[:http_rate_limit_fail_closed]
  end

  teardown do
    Setting[:security_hardening_baseline] = @prev_baseline
    Setting[:captcha_enabled] = @prev_captcha
    Setting[:password_max_age] = @prev_age
    Setting[:idle_timeout] = @prev_idle
    Setting[:http_rate_limit_fail_closed] = @prev_fail
  end

  test 'code defaults match secure baseline for key controls' do
    assert_equal true, Foreman.settings.find('captcha_enabled').default
    assert_equal 90, Foreman.settings.find('password_max_age').default
    assert_equal 30, Foreman.settings.find('idle_timeout').default
    assert_equal true, Foreman.settings.find('http_rate_limit_fail_closed').default
    assert_equal true, Foreman.settings.find('output_classification_enabled').default
  end

  test 'apply dry_run does not change settings' do
    Setting[:captcha_enabled] = false
    before = Setting[:captcha_enabled]
    result = Foreman::SecureDefaults.apply!(force: true, set_baseline: false, dry_run: true)
    assert_equal :dry_run, result[:status]
    assert_equal before, Setting[:captcha_enabled]
  end

  test 'apply force updates legacy insecure captcha default' do
    Setting[:captcha_enabled] = false
    Setting[:password_max_age] = 0
    Setting[:idle_timeout] = 60
    Setting[:http_rate_limit_fail_closed] = false

    result = Foreman::SecureDefaults.apply!(force: false, set_baseline: true, dry_run: false)
    assert_equal :applied, result[:status]
    assert_equal true, Setting[:captcha_enabled]
    assert_equal 90, Setting[:password_max_age]
    assert_equal 30, Setting[:idle_timeout]
    assert_equal true, Setting[:http_rate_limit_fail_closed]
    assert_equal Foreman::SecureDefaults.baseline_id, Setting[:security_hardening_baseline]
  end

  test 'apply without force skips customized non-legacy values' do
    Setting[:password_max_age] = 180
    result = Foreman::SecureDefaults.apply!(force: false, set_baseline: false, dry_run: false)
    skipped = result[:skipped].find { |c| c.name == 'password_max_age' }
    assert skipped, 'expected password_max_age to be skipped'
    assert_equal :skip_custom, skipped.action
    assert_equal 180, Setting[:password_max_age]
  end
end
