# frozen_string_literal: true

require 'test_helper'
require 'tmpdir'

class DigitalSignatureTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir('f032-test')
    key_path = File.join(@dir, 'signing.key')
    cert_path = File.join(@dir, 'signing.crt')
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=F032-Test')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now.utc - 60
    cert.not_after = Time.now.utc + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    File.write(key_path, key.to_pem)
    File.write(cert_path, cert.to_pem)
    @prev = ENV.to_hash.slice('FOREMAN_SIGNING_KEY_FILE', 'FOREMAN_SIGNING_CERT_FILE', 'FOREMAN_SIGNING_ENABLED')
    ENV['FOREMAN_SIGNING_KEY_FILE'] = key_path
    ENV['FOREMAN_SIGNING_CERT_FILE'] = cert_path
    ENV['FOREMAN_SIGNING_ENABLED'] = 'true'
    @actor = Struct.new(:login, :admin?).new('signer', true)
  end

  teardown do
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
    %w[FOREMAN_SIGNING_KEY_FILE FOREMAN_SIGNING_CERT_FILE FOREMAN_SIGNING_ENABLED].each do |k|
      @prev[k] ? ENV[k] = @prev[k] : ENV.delete(k)
    end
  end

  test 'authorized sign verifies and tamper fails' do
    payload = "a,b\n1,2\n"
    result = Foreman::DigitalSignature.sign!(payload, purpose: 'test', actor: @actor)
    assert Foreman::DigitalSignature.verify(result.payload, result.signature_pem,
                                            certificate_pem: result.certificate_pem)
    assert_not Foreman::DigitalSignature.verify(result.payload + '!', result.signature_pem,
                                                certificate_pem: result.certificate_pem)
    assert_includes result.signature_pem, 'BEGIN PKCS7'
    assert_equal Digest::SHA256.hexdigest(payload), result.payload_sha256
  end

  test 'unauthorized actor is rejected' do
    stranger = Struct.new(:login, :admin?, :can?).new('nope', false, false)
    def stranger.can?(*)
      false
    end
    assert_raises(Foreman::DigitalSignature::Unauthorized) do
      Foreman::DigitalSignature.sign!('x', purpose: 'test', actor: stranger)
    end
  end

  test 'missing key fails safely' do
    ENV['FOREMAN_SIGNING_KEY_FILE'] = File.join(@dir, 'missing.key')
    assert_raises(Foreman::DigitalSignature::NotConfigured) do
      Foreman::DigitalSignature.sign!('x', purpose: 'test', actor: @actor)
    end
  end

  test 'expired certificate is rejected' do
    key = OpenSSL::PKey.read(File.read(ENV['FOREMAN_SIGNING_KEY_FILE']))
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.parse('/CN=Expired')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now.utc - 3600
    cert.not_after = Time.now.utc - 60
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    File.write(ENV['FOREMAN_SIGNING_CERT_FILE'], cert.to_pem)
    assert_raises(Foreman::DigitalSignature::InvalidCertificate) do
      Foreman::DigitalSignature.sign!('x', purpose: 'test', actor: @actor)
    end
  end

  test 'wrong certificate fails verification' do
    result = Foreman::DigitalSignature.sign!('payload', purpose: 'test', actor: @actor)
    other = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 9
    cert.subject = OpenSSL::X509::Name.parse('/CN=Other')
    cert.issuer = cert.subject
    cert.public_key = other.public_key
    cert.not_before = Time.now.utc - 60
    cert.not_after = Time.now.utc + 3600
    cert.sign(other, OpenSSL::Digest.new('SHA256'))
    assert_not Foreman::DigitalSignature.verify(result.payload, result.signature_pem,
                                                certificate_pem: cert.to_pem)
  end
end
