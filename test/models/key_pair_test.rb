require 'test_helper'
require 'openssl'

class KeyPairTest < ActiveSupport::TestCase
  should belong_to(:compute_resource)

  setup do
    KeyPair.any_instance.stubs(:encryption_key).returns('25d224dd383e92a7e0c82b8bf7c985e8')
  end

  test "ensure validations" do
    key = KeyPair.new
    refute key.valid?
    assert_equal([:name, :secret, :compute_resource_id], key.errors.messages.keys)
    assert_equal(["can't be blank"], key.errors.messages.values.first.compact)
  end

  test "secret is encrypted at rest" do
    cr = FactoryBot.create(:ec2_cr)
    key = FactoryBot.create(:key_pair, compute_resource: cr, secret: 'synthetic-key-material')
    raw = key.read_attribute(:secret).to_s
    assert key.matches_prefix?(raw)
    refute_equal 'synthetic-key-material', raw
    assert_equal 'synthetic-key-material', key.secret
  end

  test "export_secret without passphrase returns plaintext material" do
    pem = OpenSSL::PKey::RSA.new(1024).to_pem
    key = FactoryBot.create(:key_pair, secret: pem)
    assert_equal pem, key.export_secret
  end

  test "export_secret with passphrase returns encrypted pem" do
    pem = OpenSSL::PKey::RSA.new(1024).to_pem
    key = FactoryBot.create(:key_pair, secret: pem)
    exported = key.export_secret(passphrase: 'synth-pass')
    assert_includes exported, 'ENCRYPTED'
    refute_equal pem, exported
    assert OpenSSL::PKey.read(exported, 'synth-pass')
  end

  context "compute resource key pair" do
    setup do
      @compute_resource = FactoryBot.create(:ec2_cr)
      @key_pair = FactoryBot.create(:key_pair, compute_resource: @compute_resource)
    end

    test "should not be active" do
      key = ComputeResourceKeyPair.new('heisneberg', '13:01:73:00:15', @key_pair.name, @key_pair.id)
      refute key.active
      assert_nil key.key_pair_id
    end

    test "should be active" do
      key = ComputeResourceKeyPair.new(@key_pair.name, '03:07:74:19:00', @key_pair.name, @key_pair.id)
      assert key.active
      refute_nil key.key_pair_id
    end

    test "should be used elsewhere" do
      another_key_pair = FactoryBot.create(:key_pair)
      key = ComputeResourceKeyPair.new(another_key_pair.name, '30:06:44:08:30', @key_pair.name, @key_pair.id)
      refute key.active
      assert key.used_elsewhere
    end

    test "should not be used elsewhere" do
      key = ComputeResourceKeyPair.new('some-key', '04:12:07:17:45', @key_pair.name, @key_pair.id)
      refute key.active
      refute key.used_elsewhere
    end
  end
end
