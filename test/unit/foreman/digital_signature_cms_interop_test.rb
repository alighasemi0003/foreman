# frozen_string_literal: true

require 'test_helper'
require 'tmpdir'

class DigitalSignatureCmsInteropTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir('f033-test')
    key_path = File.join(@dir, 'signing.key')
    cert_path = File.join(@dir, 'signing.crt')
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=F033-CMS')
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
    @actor = Struct.new(:login, :admin?).new('cms', true)
  end

  teardown do
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
    %w[FOREMAN_SIGNING_KEY_FILE FOREMAN_SIGNING_CERT_FILE FOREMAN_SIGNING_ENABLED].each do |k|
      @prev[k] ? ENV[k] = @prev[k] : ENV.delete(k)
    end
  end

  test 'contract documents detached PEM and DER only' do
    c = Foreman::DigitalSignature::CmsInterop.supported_contract
    assert_equal true, c[:detached]
    assert_equal false, c[:attached]
    assert_includes c[:encodings], 'PEM'
    assert_includes c[:encodings], 'DER'
  end

  test 'PEM and DER signatures verify; content mismatch fails' do
    result = Foreman::DigitalSignature.sign!("x,y\n1,2\n", purpose: 'cms', actor: @actor)
    assert_includes result.signature_pem, 'BEGIN PKCS7'
    assert result.signature_der.bytesize.positive?
    assert_equal 'rsa-sha256', result.signature_algorithm
    assert Foreman::DigitalSignature.verify(result.payload, result.signature_pem,
                                            certificate_pem: result.certificate_pem)
    assert Foreman::DigitalSignature.verify(result.payload, result.signature_der,
                                            certificate_pem: result.certificate_pem)
    assert_not Foreman::DigitalSignature.verify(result.payload + 'z', result.signature_der,
                                                certificate_pem: result.certificate_pem)

    export = result.as_export(filename: 't.csv', media_type: 'text/csv', classification: 'internal')
    assert_equal false, export[:attached_content]
    assert_equal true, export[:detached_content]
    assert_equal 'internal', export[:classification]
    assert export[:signature_der_base64].present?
  end

  test 'OpenSSL CLI accepts PEM and DER detached artifacts' do
    skip 'openssl binary required' unless system('openssl', 'version', out: File::NULL, err: File::NULL)

    result = Foreman::DigitalSignature.sign!("a,b\n", purpose: 'cli', actor: @actor)
    Dir.mktmpdir('f033-cli') do |d|
      paths = Foreman::DigitalSignature::CmsInterop.write_detached_artifacts(result, directory: d)
      pem = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content], signature_path: paths[:signature_pem],
        ca_path: paths[:certificate], inform: 'PEM'
      )
      der = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content], signature_path: paths[:signature_der],
        ca_path: paths[:certificate], inform: 'DER'
      )
      assert pem[:ok], pem[:stderr]
      assert der[:ok], der[:stderr]

      File.binwrite(paths[:content], result.payload + 'nope')
      bad = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content], signature_path: paths[:signature_pem],
        ca_path: paths[:certificate], inform: 'PEM'
      )
      assert_not bad[:ok]
    end
  end

  test 'signer certificate is present inside SignedData' do
    result = Foreman::DigitalSignature.sign!('body', purpose: 'certs', actor: @actor)
    p7 = Foreman::DigitalSignature::CmsInterop.parse_signature(result.signature_pem)
    subjects = Foreman::DigitalSignature::CmsInterop.signer_certificates(p7).map { |c| c.subject.to_s }
    assert_includes subjects, result.signer_subject
    assert_includes result.cms_certificates_included, result.signer_subject
  end
end
