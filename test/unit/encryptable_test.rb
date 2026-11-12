require 'test_helper'

class EncryptableTest < ActiveSupport::TestCase
  setup do
    # default test behaviour should be no encryption
    ComputeResource.any_instance.stubs(:encryption_key).returns(nil)
  end

  def cr_with_encryption_key
    stub_encryption_key(FactoryBot.build(:ec2_cr, password: 'encrypted-aXVpUzdTSTArRlFwR1RKTy90QWFKQVZDOERGQXhteUFaMG1xVnMxWmFuaz0tLTJHcnlIUDV3N0RrcjhkMWRzdWtJNkE9PQ==--e9227b0757885a231036fe9a7e4f959cfdf66f56'))
  end

  def cr_with_long_encryption_key
    stub_encryption_key(FactoryBot.build(:ec2_cr, password: 'encrypted-NEN1YVJtdWdaaTdlOHdiUXRHd29nWUZsOHc1UjdMb3p1MFZLenlLekFEbz0tLVA0MGVzUEorUDlJZHVUV2F6azUzUEE9PQ==--9f45d5c88ec582eeb48ebb906ae0a66345ded0fa'), '25d224dd383e92a7e0c82b8bf7c985e815f34cf5')
  end

  def stub_encryption_key(model, key = '25d224dd383e92a7e0c82b8bf7c985e8')
    model.stubs(:encryption_key).returns(key)
    model
  end

  test "encrypts?(:password) is true" do
    assert ComputeResource.encrypts?(:password)
  end

  test "encryptable_fields include?(:password)" do
    assert ComputeResource.encryptable_fields.include?(:password)
  end

  test "is_encryptable? is false when key is empty" do
    cr = FactoryBot.build_stubbed(:ec2_cr)
    cr.stubs(:encryption_key).returns(nil)
    refute cr.is_encryptable?('foo')
  end

  test "is_decryptable? is false when key is empty" do
    cr = FactoryBot.build_stubbed(:ec2_cr)
    cr.stubs(:encryption_key).returns(nil)
    refute cr.is_decryptable?('encrypted-WkQyR0xMVXZCT2hRTmVGaTNIWlY3RkoxM1M4')
  end

  test "this string IS encryptable and NOT decryptable" do
    str = "abcd1234"
    compute_resource = cr_with_encryption_key
    assert compute_resource.is_encryptable?(str)
    refute compute_resource.is_decryptable?(str)
  end

  test "this string is NOT encryptable and IS decryptable" do
    str = "encrypted-WkQyR0xMVXZCT2hRTmVGaTNIWlY3RkoxM1M4"
    compute_resource = cr_with_encryption_key
    refute compute_resource.is_encryptable?(str)
    assert compute_resource.is_decryptable?(str)
  end

  test "string is NOT encrypted AGAIN upon save if it is not changed" do
    compute_resource = cr_with_encryption_key
    orig_pass = compute_resource.password
    orig_pass_in_db = compute_resource.password_in_db
    refute compute_resource.is_decryptable?(orig_pass)
    assert compute_resource.is_decryptable?(orig_pass_in_db)
    assert compute_resource.save!
    compute_resource.reload
    new_pass = compute_resource.password
    new_pass_in_db = compute_resource.password_in_db
    assert_equal orig_pass, new_pass
    assert_equal orig_pass_in_db, new_pass_in_db
    assert compute_resource.is_decryptable?(new_pass_in_db)
  end

  test "string is re-encrypted upon save if password changed" do
    compute_resource = cr_with_encryption_key
    orig_pass = compute_resource.password
    orig_pass_in_db = compute_resource.password_in_db
    compute_resource.password = "3333333"
    assert compute_resource.save!
    compute_resource.reload
    new_pass = compute_resource.password
    new_pass_in_db = compute_resource.password_in_db
    refute_equal orig_pass, new_pass
    refute_equal orig_pass_in_db, new_pass_in_db
  end

  test "does not decrypt if string is not decryptable and returns database value" do
    compute_resource = stub_encryption_key(FactoryBot.build_stubbed(:compute_resource, password: '1234567'))
    orig_pass = compute_resource.password
    orig_pass_in_db = compute_resource.password_in_db
    refute compute_resource.is_decryptable?(orig_pass_in_db)
    refute compute_resource.is_decryptable?(orig_pass)
    assert_equal orig_pass, orig_pass_in_db
  end

  test "encrypt successfully" do
    compute_resource = cr_with_encryption_key
    plain_str = "secretpassword"
    encrypted_str = compute_resource.encrypt_field(plain_str)
    refute_equal plain_str, encrypted_str
    assert compute_resource.matches_prefix?(encrypted_str)
    assert compute_resource.is_decryptable?(encrypted_str)
  end

  test "encrypt unsuccessfully refuses plaintext and logs once" do
    EncryptValue.reset_warnings
    compute_resource = cr_with_encryption_key
    ActiveSupport::MessageEncryptor.any_instance.stubs(:encrypt_and_sign).raises(StandardError, 'Encryption error')
    compute_resource.expects(:puts_and_logs).once
    err = assert_raises(Foreman::Exception) { compute_resource.encrypt_field('secretpassword') }
    refute_includes err.message, 'secretpassword'
    refute_includes err.message, 'Encryption error'
    # second failure still raises; warning logged only once
    assert_raises(Foreman::Exception) { compute_resource.encrypt_field('secretpassword') }
  end

  test "valid key encrypts and decrypts roundtrip" do
    compute_resource = cr_with_encryption_key
    plain = 'synthetic-f005-roundtrip'
    encrypted = compute_resource.encrypt_field(plain)
    assert compute_resource.matches_prefix?(encrypted)
    assert_equal plain, compute_resource.decrypt_field(encrypted)
  end

  test "missing key rejects sensitive save" do
    cr = FactoryBot.build(:ec2_cr, password: 'synthetic-f005-missing-key')
    cr.stubs(:encryption_key).returns(nil)
    assert_raises(Foreman::Exception) { cr.save! }
    refute cr.persisted?
  end

  test "encryption exception rejects sensitive save" do
    cr = FactoryBot.build(:ec2_cr, password: 'synthetic-f005-encrypt-fail')
    stub_encryption_key(cr)
    ActiveSupport::MessageEncryptor.any_instance.stubs(:encrypt_and_sign).raises(StandardError, 'encrypt boom')
    assert_raises(Foreman::Exception) { cr.save! }
    refute cr.persisted?
  end

  test "failed encryption leaves database unchanged" do
    compute_resource = cr_with_encryption_key
    assert compute_resource.save!
    orig_in_db = compute_resource.reload.password_in_db
    assert compute_resource.matches_prefix?(orig_in_db)

    ActiveSupport::MessageEncryptor.any_instance.stubs(:encrypt_and_sign).raises(StandardError, 'encrypt boom')
    compute_resource.password = 'synthetic-f005-should-not-persist'
    assert_raises(Foreman::Exception) { compute_resource.save! }
    assert_equal orig_in_db, compute_resource.reload.password_in_db
  end

  test "already encrypted value is not double-encrypted" do
    compute_resource = cr_with_encryption_key
    once = compute_resource.encrypt_field('synthetic-f005-once')
    twice = compute_resource.encrypt_field(once)
    assert_equal once, twice
    assert_equal 1, twice.to_s.scan(EncryptValue::ENCRYPTION_PREFIX).length
  end

  test "updating unrelated attributes does not corrupt encrypted password" do
    compute_resource = cr_with_encryption_key
    assert compute_resource.save!
    orig_in_db = compute_resource.reload.password_in_db
    compute_resource.name = "#{compute_resource.name}-f005"
    assert compute_resource.save!
    assert_equal orig_in_db, compute_resource.reload.password_in_db
    assert_equal compute_resource.decrypt_field(orig_in_db), compute_resource.password
  end

  test "encryption failure messages omit plaintext secrets" do
    EncryptValue.reset_warnings
    compute_resource = cr_with_encryption_key
    ActiveSupport::MessageEncryptor.any_instance.stubs(:encrypt_and_sign).raises(StandardError, 'leak-synthetic-f005')
    logged = []
    compute_resource.stubs(:puts_and_logs).with { |msg| logged << msg; true }
    err = assert_raises(Foreman::Exception) { compute_resource.encrypt_field('synthetic-f005-log-check') }
    refute_includes err.message, 'synthetic-f005-log-check'
    refute_includes err.message, 'leak-synthetic-f005'
    logged.each do |msg|
      refute_includes msg, 'synthetic-f005-log-check'
      refute_includes msg, 'leak-synthetic-f005'
    end
  end

  test "decrypt successfully" do
    compute_resource = cr_with_encryption_key
    plain_str = "secretpassword"
    encrypted_str = compute_resource.encrypt_field(plain_str)
    decrypted_str = compute_resource.decrypt_field(encrypted_str)
    refute_equal encrypted_str, decrypted_str
    assert_equal plain_str, decrypted_str
  end

  test "decrypt successfully with over-sized key" do
    compute_resource = cr_with_long_encryption_key
    plain_str = "secretpassword"
    encrypted_str = compute_resource.encrypt_field(plain_str)
    decrypted_str = compute_resource.decrypt_field(encrypted_str)
    refute_equal encrypted_str, decrypted_str
    assert_equal plain_str, decrypted_str
  end

  test "decrypt unsuccessfully logs error once" do
    EncryptValue.reset_warnings
    compute_resource = stub_encryption_key(FactoryBot.build_stubbed(:ec2_cr, password: 'encrypted-invalid'))
    compute_resource.expects(:puts_and_logs).once
    decrypted_str = compute_resource.password
    assert_equal 'encrypted-invalid', decrypted_str
    compute_resource.password
  end

  test "encrypt_field returns nil if password is nil" do
    compute_resource = cr_with_encryption_key
    encrypted_str = compute_resource.encrypt_field(nil)
    assert_nil encrypted_str
  end

  test "encrypt_field refuses plaintext storage when key is missing" do
    cr = FactoryBot.build_stubbed(:ec2_cr)
    cr.stubs(:encryption_key).returns(nil)
    assert_raises(Foreman::Exception) { cr.encrypt_field('secretpassword') }
  end

  test "encryption_key reads ENCRYPTION_KEY_FILE when ENV key absent" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'encryption_key')
      File.write(path, "25d224dd383e92a7e0c82b8bf7c985e815f34cf5\n")
      old_key = ENV['ENCRYPTION_KEY']
      old_file = ENV['ENCRYPTION_KEY_FILE']
      begin
        ENV.delete('ENCRYPTION_KEY')
        ENV['ENCRYPTION_KEY_FILE'] = path
        ComputeResource.any_instance.unstub(:encryption_key)
        cr = FactoryBot.build_stubbed(:ec2_cr)
        assert_equal '25d224dd383e92a7e0c82b8bf7c985e815f34cf5', cr.encryption_key
        encrypted = cr.encrypt_field('file-key-secret')
        assert cr.matches_prefix?(encrypted)
        assert_equal 'file-key-secret', cr.decrypt_field(encrypted)
      ensure
        ENV['ENCRYPTION_KEY'] = old_key
        ENV['ENCRYPTION_KEY_FILE'] = old_file
        ComputeResource.any_instance.stubs(:encryption_key).returns(nil)
      end
    end
  end
end
