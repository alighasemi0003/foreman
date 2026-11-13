# frozen_string_literal: true

require 'open3'
require 'tempfile'

module Foreman
  class DigitalSignature
    # F-033: CMS/PKCS#7 interoperability helpers (independent OpenSSL CLI checks).
    # Cryptographic verify ≠ full PKI trust/revocation assessment.
    module CmsInterop
      CONTENT_TYPE_PEM = 'application/pkcs7-signature'
      CONTENT_TYPE_DER = 'application/pkcs7-mime'
      FILE_EXTENSION = '.p7s'

      module_function

      # Supported contract (explicit non-claims documented in docs).
      def supported_contract
        {
          profile: 'CMS/PKCS#7 SignedData',
          attached: false,
          detached: true,
          encodings: %w[PEM DER],
          digest: 'SHA256',
          content_inclusion: 'detached external content',
          certificates_in_signeddata: 'signer certificate included by OpenSSL::PKCS7.sign',
          multiple_signers: false,
          revocation_checked_by_default: false,
          trust_model: 'verifier-supplied trust anchor / CAfile'
        }
      end

      # Run OpenSSL CLI verification against PEM or DER detached signature.
      # Returns hash with :ok, :command, :stdout, :stderr, :exitstatus.
      def openssl_cli_verify(content_path:, signature_path:, ca_path:, inform: 'PEM',
                             check_trust: false)
        inform = inform.to_s.upcase
        raise ArgumentError, "inform must be PEM or DER" unless %w[PEM DER].include?(inform)

        # Prefer `openssl cms` (CMS); fall back to `smime` for older layouts.
        args = [
          'openssl', 'cms', '-verify',
          '-in', signature_path,
          '-inform', inform,
          '-content', content_path,
          '-CAfile', ca_path,
          '-binary'
        ]
        args << '-noverify' unless check_trust

        stdout, stderr, status = Open3.capture3(*args)
        if status.exitstatus != 0 && stderr.to_s.match?(/unknown option|Invalid command|cms: command/i)
          args = [
            'openssl', 'smime', '-verify',
            '-in', signature_path,
            '-inform', inform,
            '-content', content_path,
            '-CAfile', ca_path,
            '-binary'
          ]
          args << '-noverify' unless check_trust
          stdout, stderr, status = Open3.capture3(*args)
        end

        {
          ok: status.success?,
          command: args.join(' '),
          stdout: stdout.to_s,
          stderr: stderr.to_s,
          exitstatus: status.exitstatus,
          trust_chain_checked: check_trust
        }
      end

      def write_detached_artifacts(result, directory:, basename: 'document')
        content = File.join(directory, "#{basename}.csv")
        pem = File.join(directory, "#{basename}#{FILE_EXTENSION}")
        der = File.join(directory, "#{basename}.p7s.der")
        cert = File.join(directory, "#{basename}-signer.crt")
        File.binwrite(content, result.payload)
        File.write(pem, result.signature_pem)
        File.binwrite(der, result.signature_der)
        File.write(cert, result.certificate_pem)
        {
          content: content,
          signature_pem: pem,
          signature_der: der,
          certificate: cert,
          content_type_pem: CONTENT_TYPE_PEM,
          content_type_der: CONTENT_TYPE_DER
        }
      end

      def parse_signature(pem_or_der)
        OpenSSL::PKCS7.new(pem_or_der)
      end

      def signer_certificates(pkcs7)
        Array(pkcs7.certificates)
      end
    end
  end
end
