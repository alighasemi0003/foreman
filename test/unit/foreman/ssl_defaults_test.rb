# frozen_string_literal: true

require 'test_helper'

class ForemanSslDefaultsTest < ActiveSupport::TestCase
  test 'production with FOREMAN_REQUIRE_SSL unset forces require_ssl true' do
    settings = { require_ssl: false }
    Foreman::SslDefaults.apply!(settings, env: {}, rails_env: 'production')
    assert_equal true, settings[:require_ssl]
  end

  test 'production with FOREMAN_REQUIRE_SSL=true leaves loader value true' do
    settings = { require_ssl: true }
    env = { 'FOREMAN_REQUIRE_SSL' => 'true' }
    Foreman::SslDefaults.apply!(settings, env: env, rails_env: 'production')
    assert_equal true, settings[:require_ssl]
  end

  test 'production with FOREMAN_REQUIRE_SSL=false keeps require_ssl false' do
    settings = { require_ssl: false }
    env = { 'FOREMAN_REQUIRE_SSL' => 'false' }
    Foreman::SslDefaults.apply!(settings, env: env, rails_env: 'production')
    assert_equal false, settings[:require_ssl]
  end

  test 'production with FOREMAN_REQUIRE_SSL present does not override true from loader' do
    settings = { require_ssl: true }
    env = { 'FOREMAN_REQUIRE_SSL' => 'false' }
    # Env loader already set false; apply! must not force true when key is present
    settings[:require_ssl] = false
    Foreman::SslDefaults.apply!(settings, env: env, rails_env: 'production')
    assert_equal false, settings[:require_ssl]
  end

  test 'test environment does not force require_ssl' do
    settings = { require_ssl: false }
    Foreman::SslDefaults.apply!(settings, env: {}, rails_env: 'test')
    assert_equal false, settings[:require_ssl]
  end

  test 'development environment does not force require_ssl' do
    settings = { require_ssl: false }
    Foreman::SslDefaults.apply!(settings, env: {}, rails_env: 'development')
    assert_equal false, settings[:require_ssl]
  end

  test 'session Secure remains aligned with require_ssl and HttpOnly SameSite preserved' do
    assert_equal !!SETTINGS[:require_ssl], !!Rails.application.config.session_options[:secure]
    assert_equal true, Rails.application.config.session_options[:httponly]
    assert_equal :lax, Rails.application.config.session_options[:same_site]
  end
end
