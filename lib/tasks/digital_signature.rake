# frozen_string_literal: true

namespace :security do
  desc 'F-032: sign a synthetic document and verify (requires FOREMAN_SIGNING_* files)'
  task digital_signature_demo: :environment do
    require 'json'
    require 'base64'
    require 'tmpdir'

    unless Foreman::DigitalSignature.configured?
      abort('Configure FOREMAN_SIGNING_KEY_FILE and FOREMAN_SIGNING_CERT_FILE first')
    end

    actor = Struct.new(:login, :admin?).new('f032-demo', true)
    payload = "name,value\nalpha,1\n"
    result = Foreman::DigitalSignature.sign!(payload, purpose: 'demo:synthetic_csv', actor: actor)
    ok = Foreman::DigitalSignature.verify(
      result.payload,
      result.signature_pem,
      certificate_pem: result.certificate_pem
    )
    tampered = Foreman::DigitalSignature.verify(
      result.payload + 'x',
      result.signature_pem,
      certificate_pem: result.certificate_pem
    )

    Dir.mktmpdir('f032') do |dir|
      content = File.join(dir, 'document.csv')
      sig = File.join(dir, 'document.csv.p7s')
      cert = File.join(dir, 'signer.crt')
      File.binwrite(content, result.payload)
      File.write(sig, result.signature_pem)
      File.write(cert, result.certificate_pem)
      # Independent OpenSSL CLI verification (CMS/PKCS#7)
      cli = system(
        'openssl', 'smime', '-verify',
        '-in', sig, '-inform', 'PEM',
        '-content', content,
        '-CAfile', cert,
        '-binary', '-noverify',
        out: File::NULL, err: File::NULL
      )
      puts JSON.pretty_generate(
        task: 'F-032',
        ruby_verify: ok,
        tamper_verify: tampered,
        openssl_smime_verify: cli == true,
        certificate_fingerprint_sha256: result.certificate_fingerprint_sha256,
        payload_sha256: result.payload_sha256,
        signer_subject: result.signer_subject,
        signature_format: Foreman::DigitalSignature::SIGNATURE_FORMAT
      )
      abort('verification failed') unless ok && tampered == false && cli
    end
  end
end
