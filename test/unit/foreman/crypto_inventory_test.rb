# frozen_string_literal: true

require 'test_helper'
require 'foreman/crypto_inventory'

class Foreman::CryptoInventoryTest < ActiveSupport::TestCase
  test 'report does not claim FIPS compliance' do
    report = Foreman::CryptoInventory.report
    assert_equal 'NOT_CLAIMED', report[:fips_compliance_claim]
    assert report[:openssl].key?(:fips_mode)
    assert_includes report[:application][:password_approved_for_new], :bcrypt
    assert_equal 'HS256', report[:application][:jwt_algorithm]
    assert_match(/aes-256-cbc/, report[:application][:encrypt_value])
    assert_match(/VncDes|DES/, report[:application][:vnc_des])
  end

  test 'openssl state records message encryptor cipher without enabling fips' do
    before = OpenSSL.fips_mode
    state = Foreman::CryptoInventory.openssl_state
    assert_equal before, OpenSSL.fips_mode, 'inventory must not flip process FIPS mode'
    assert_equal 'aes-256-cbc', state[:message_encryptor_default_cipher]
  end

  test 'isolated fips probe runs in subprocess and leaves parent fips_mode unchanged' do
    before = OpenSSL.fips_mode
    probe = Foreman::CryptoInventory.isolated_fips_provider_probe
    assert_equal before, OpenSSL.fips_mode
    assert_equal 'isolated_subprocess_OPENSSL_CONF', probe[:probe]
    assert probe[:result].is_a?(Hash)
  end
end
