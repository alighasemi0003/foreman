# frozen_string_literal: true

require 'test_helper'
require 'foreman/session_cookie_encryptor'

class ForemanSessionCookieEncryptorTest < ActiveSupport::TestCase
  setup do
    Foreman::SessionCookieEncryptor.reset_encryptor!
    @sid = SecureRandom.hex(16)
  end

  teardown do
    Foreman::SessionCookieEncryptor.reset_encryptor!
  end

  test 'encrypt wraps public sid and decrypt roundtrips' do
    sealed = Foreman::SessionCookieEncryptor.encrypt(@sid)
    assert Foreman::SessionCookieEncryptor.encrypted?(sealed)
    assert_operator sealed.length, :<, 4000
    refute_equal @sid, sealed
    refute_includes sealed, @sid
    assert_equal @sid, Foreman::SessionCookieEncryptor.decrypt(sealed)
  end

  test 'legacy plain hex cookie is rejected' do
    assert_nil Foreman::SessionCookieEncryptor.decrypt(@sid)
    assert_nil Foreman::SessionCookieEncryptor.decrypt('not-a-valid-cookie')
  end

  test 'tampered ciphertext is rejected' do
    sealed = Foreman::SessionCookieEncryptor.encrypt(@sid)
    tampered = sealed.sub(/.\z/, sealed[-1] == 'A' ? 'B' : 'A')
    assert_nil Foreman::SessionCookieEncryptor.decrypt(tampered)
  end

  test 'wrong key rejects cookie' do
    other_key = '1' * ActiveSupport::MessageEncryptor.key_len
    forged = "#{Foreman::SessionCookieEncryptor::PREFIX}" \
             "#{ActiveSupport::MessageEncryptor.new(other_key).encrypt_and_sign(@sid)}"
    assert_nil Foreman::SessionCookieEncryptor.decrypt(forged)
  end

  test 'blank values are nil' do
    assert_nil Foreman::SessionCookieEncryptor.encrypt(nil)
    assert_nil Foreman::SessionCookieEncryptor.decrypt(nil)
    assert_nil Foreman::SessionCookieEncryptor.decrypt('')
  end
end
