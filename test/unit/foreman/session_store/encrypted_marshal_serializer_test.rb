# frozen_string_literal: true

require 'test_helper'
require 'foreman/session_store/encrypted_marshal_serializer'

class ForemanSessionStoreEncryptedMarshalSerializerTest < ActiveSupport::TestCase
  Serializer = Foreman::SessionStore::EncryptedMarshalSerializer

  setup do
    Serializer.reset_encryptor!
    @payload = {
      'user' => 42,
      'expires_at' => 1.hour.from_now.utc.to_s,
      'reauthenticated_at' => Time.now.utc.to_i,
    }
  end

  teardown do
    Serializer.reset_encryptor!
  end

  test 'dump produces ARSESS1 encrypted payload without plaintext keys' do
    stored = Serializer.dump(@payload)
    assert stored.start_with?(Serializer::PREFIX)
    refute_includes stored, 'user'
    refute_includes stored, 'reauthenticated_at'
    refute Serializer.legacy_payload?(stored)
    assert Serializer.encrypted_payload?(stored)
  end

  test 'round trip restores session hash' do
    stored = Serializer.dump(@payload)
    loaded = Serializer.load(stored)
    assert_equal 42, loaded['user']
    assert_equal @payload['reauthenticated_at'], loaded['reauthenticated_at']
  end

  test 'legacy base64 marshal remains readable' do
    legacy = ::Base64.encode64(Marshal.dump(@payload))
    assert Serializer.legacy_payload?(legacy)
    loaded = Serializer.load(legacy)
    assert_equal 42, loaded['user']
  end

  test 'tampered ciphertext yields nil' do
    stored = Serializer.dump(@payload)
    tampered = stored + 'x'
    assert_nil Serializer.load(tampered)
  end

  test 'wrong key fails safely' do
    stored = Serializer.dump(@payload)
    Serializer.reset_encryptor!
    # Swap secret_key_base temporarily
    app = Rails.application
    original = app.secret_key_base
    begin
      app.secret_key_base = '0' * 64
      # key_generator is memoized on the app — rebuild path via reset + new generator use
      app.instance_variable_set(:@key_generator, nil) if app.instance_variable_defined?(:@key_generator)
      Serializer.reset_encryptor!
      assert_nil Serializer.load(stored)
    ensure
      app.secret_key_base = original
      app.instance_variable_set(:@key_generator, nil) if app.instance_variable_defined?(:@key_generator)
      Serializer.reset_encryptor!
    end
  end

  test 'session model uses encrypted serializer for new writes' do
    require 'active_record/session_store/session'
    assert_equal Serializer, ActiveRecord::SessionStore::Session.serializer_class

    record = ActiveRecord::SessionStore::Session.new(session_id: "test-#{SecureRandom.hex(8)}", data: @payload)
    assert record.save, record.errors.full_messages.to_sentence
    raw = record.read_attribute_before_type_cast('data').to_s
    assert raw.start_with?(Serializer::PREFIX), 'expected encrypted column value'
    refute_includes raw, 'reauthenticated_at'

    reloaded = ActiveRecord::SessionStore::Session.find_by_session_id(record.session_id)
    assert_equal 42, reloaded.data['user']
  ensure
    record&.destroy
  end
end
