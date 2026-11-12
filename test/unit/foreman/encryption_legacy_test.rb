# frozen_string_literal: true

require 'test_helper'

class ForemanEncryptionLegacyTest < ActiveSupport::TestCase
  setup do
    @key = '25d224dd383e92a7e0c82b8bf7c985e815f34cf5'
    JwtSecret.any_instance.stubs(:encryption_key).returns(@key)
    ComputeResource.any_instance.stubs(:encryption_key).returns(@key)
    HttpProxy.any_instance.stubs(:encryption_key).returns(@key)
  end

  test 'inventory counts plaintext JwtSecret candidates without disclosing values' do
    user = FactoryBot.create(:user)
    secret = JwtSecret.create!(user: user, token: 'synthPlainJwtSecretValue01')
    # Bypass encrypt callbacks to simulate legacy plaintext at rest
    secret.update_column(:token, 'synthPlainJwtSecretValue01')

    inv = Foreman::EncryptionLegacy.new(dry_run: true).inventory
    row = inv.find { |r| r[:model] == 'JwtSecret' }
    assert row
    assert_includes row[:candidate_ids], secret.id
    refute_match(/synthPlainJwtSecretValue01/, row.inspect)
  end

  test 'dry-run does not mutate plaintext candidates' do
    user = FactoryBot.create(:user)
    secret = JwtSecret.create!(user: user, token: 'synthPlainJwtSecretValue02')
    secret.update_column(:token, 'synthPlainJwtSecretValue02')
    before = secret.reload.read_attribute(:token)

    migrator = Foreman::EncryptionLegacy.new(dry_run: true)
    migrator.remediate!
    assert_equal before, secret.reload.read_attribute(:token)
    assert_equal 1, migrator.summary[:would_encrypt]
  end

  test 'migration encrypts at rest and preserves logical JwtSecret token' do
    user = FactoryBot.create(:user)
    plain = 'synthPlainJwtSecretValue03'
    secret = JwtSecret.create!(user: user, token: plain)
    secret.update_column(:token, plain)

    token = JwtToken.encode(user, plain, expiration: 3600).to_s

    migrator = Foreman::EncryptionLegacy.new(dry_run: false)
    outcome = migrator.send(:remediate_record, secret, :token)
    secret.reload

    assert_equal :encrypted, outcome.status
    assert secret.read_attribute(:token).start_with?(EncryptValue::ENCRYPTION_PREFIX)
    assert_equal plain, secret.token

    # Logical HMAC material unchanged — previously issued JWT still verifies.
    JwtSecret.stubs(:find_by).with(user_id: user.id).returns(secret)
    jwt = JwtToken.new(token)
    assert jwt.decode
  end

  test 'repeated migration does not double-encrypt' do
    user = FactoryBot.create(:user)
    plain = 'synthPlainJwtSecretValue04'
    secret = JwtSecret.create!(user: user, token: plain)
    secret.update_column(:token, plain)

    Foreman::EncryptionLegacy.new(dry_run: false).remediate!
    first = secret.reload.read_attribute(:token)
    assert first.start_with?(EncryptValue::ENCRYPTION_PREFIX)

    migrator = Foreman::EncryptionLegacy.new(dry_run: false)
    migrator.remediate!
    second = secret.reload.read_attribute(:token)
    assert_equal first, second
    assert_equal 1, first.to_s.scan(EncryptValue::ENCRYPTION_PREFIX).length
    assert_equal 0, migrator.summary[:encrypted].to_i
  end

  test 'skips message-encryptor shaped values missing prefix' do
    user = FactoryBot.create(:user)
    odd = "#{'A' * 40}--#{'a' * 40}"
    secret = JwtSecret.create!(user: user, token: 'tmp')
    secret.update_column(:token, odd)

    migrator = Foreman::EncryptionLegacy.new(dry_run: false)
    migrator.remediate!
    assert_equal odd, secret.reload.read_attribute(:token)
    assert_equal 1, migrator.summary[:skipped_ineligible]
  end
end
