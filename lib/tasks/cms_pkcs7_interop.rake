# frozen_string_literal: true

namespace :security do
  desc 'F-033: CMS/PKCS#7 interop — Foreman sign + independent OpenSSL cms/smime verify'
  task cms_pkcs7_interop: :environment do
    require 'json'
    require 'tmpdir'

    unless Foreman::DigitalSignature.configured?
      abort('Configure FOREMAN_SIGNING_KEY_FILE and FOREMAN_SIGNING_CERT_FILE first')
    end

    actor = Struct.new(:login, :admin?).new('f033-interop', true)
    payload = "col_a,col_b\ninterop,1\n"
    result = Foreman::DigitalSignature.sign!(payload, purpose: 'interop:cms_pkcs7', actor: actor)

    ruby_pem = Foreman::DigitalSignature.verify(
      result.payload, result.signature_pem, certificate_pem: result.certificate_pem
    )
    ruby_der = Foreman::DigitalSignature.verify(
      result.payload, result.signature_der, certificate_pem: result.certificate_pem
    )
    tamper = Foreman::DigitalSignature.verify(
      result.payload + 'TAMPER', result.signature_pem, certificate_pem: result.certificate_pem
    )
    corrupt_sig = begin
      # Truncate DER so SignedData is structurally invalid / non-verifying.
      bad = result.signature_der.byteslice(0, [32, result.signature_der.bytesize / 4].max)
      Foreman::DigitalSignature.verify(result.payload, bad, certificate_pem: result.certificate_pem)
    rescue OpenSSL::PKCS7::PKCS7Error, ArgumentError, TypeError
      false
    end

    Dir.mktmpdir('f033') do |dir|
      paths = Foreman::DigitalSignature::CmsInterop.write_detached_artifacts(
        result, directory: dir, basename: 'foreman-export'
      )
      pem_cli = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content],
        signature_path: paths[:signature_pem],
        ca_path: paths[:certificate],
        inform: 'PEM',
        check_trust: false
      )
      der_cli = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content],
        signature_path: paths[:signature_der],
        ca_path: paths[:certificate],
        inform: 'DER',
        check_trust: false
      )
      # Detached mismatch
      File.binwrite(paths[:content], result.payload + 'x')
      mismatch = Foreman::DigitalSignature::CmsInterop.openssl_cli_verify(
        content_path: paths[:content],
        signature_path: paths[:signature_pem],
        ca_path: paths[:certificate],
        inform: 'PEM',
        check_trust: false
      )

      p7 = Foreman::DigitalSignature::CmsInterop.parse_signature(result.signature_pem)
      report = {
        task: 'F-033',
        prerequisite: 'F-032',
        contract: Foreman::DigitalSignature::CmsInterop.supported_contract,
        ruby_verify_pem: ruby_pem,
        ruby_verify_der: ruby_der,
        tamper_content_ruby: tamper,
        corrupt_signature_ruby: corrupt_sig,
        openssl_cli_pem: pem_cli.slice(:ok, :command, :trust_chain_checked, :exitstatus),
        openssl_cli_der: der_cli.slice(:ok, :command, :trust_chain_checked, :exitstatus),
        openssl_cli_content_mismatch: mismatch.slice(:ok, :exitstatus),
        digest_algorithm: result.digest_algorithm,
        signature_algorithm: result.signature_algorithm,
        signer_subject: result.signer_subject,
        certificate_fingerprint_sha256: result.certificate_fingerprint_sha256,
        cms_certificates_included: result.cms_certificates_included,
        pkcs7_type: p7.type.to_s,
        signature_pem_bytes: result.signature_pem.bytesize,
        signature_der_bytes: result.signature_der.bytesize
      }
      puts JSON.pretty_generate(report)

      ok = ruby_pem && ruby_der && tamper == false && corrupt_sig == false &&
           pem_cli[:ok] && der_cli[:ok] && mismatch[:ok] == false
      abort('F-033 CMS/PKCS#7 interoperability checks failed') unless ok
    end
  end
end
