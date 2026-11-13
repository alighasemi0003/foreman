# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'digest'

# F-032: application-level CMS/PKCS#7 detached signatures over exact export bytes.
# Does not sign arbitrary HTTP responses. Does not reuse ENCRYPTION_KEY.
module Foreman
  class DigitalSignature
    Error = Class.new(StandardError)
    NotConfigured = Class.new(Error)
    Unauthorized = Class.new(Error)
    InvalidCertificate = Class.new(Error)

    FORMAT = 'foreman-signed-export-v1'
    SIGNATURE_FORMAT = 'PKCS7-DETACHED'
    FLAGS = OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY
    DIGEST = 'SHA256'

    Result = Struct.new(
      :payload, :signature_pem, :certificate_pem, :certificate_fingerprint_sha256,
      :signer_subject, :signed_at, :payload_sha256, :digest_algorithm,
      keyword_init: true
    ) do
      def as_export(filename:, media_type:, classification: nil)
        {
          format: FORMAT,
          payload_media_type: media_type,
          payload_filename: filename,
          payload_sha256: payload_sha256,
          payload_base64: Base64.strict_encode64(payload),
          signature_format: SIGNATURE_FORMAT,
          signature_pem: signature_pem,
          certificate_pem: certificate_pem,
          certificate_fingerprint_sha256: certificate_fingerprint_sha256,
          digest_algorithm: digest_algorithm,
          signed_at: signed_at,
          signer_subject: signer_subject,
          classification: classification
        }
      end
    end

    class << self
      def enabled?
        ActiveModel::Type::Boolean.new.cast(ENV.fetch('FOREMAN_SIGNING_ENABLED', 'false')) &&
          key_path.present? && cert_path.present?
      end

      def configured?
        key_path.present? && cert_path.present? &&
          File.file?(key_path) && File.file?(cert_path)
      end

      def authorize!(user)
        raise Unauthorized, 'authentication required' unless user
        return true if user.admin?
        return true if user.respond_to?(:can?) && user.can?(:view_hosts)

        raise Unauthorized, 'not authorized to request digital signatures'
      end

      # Sign exact +payload+ bytes (canonical representation presented to the user).
      def sign!(payload, purpose:, actor: User.current)
        raise NotConfigured, 'signing key/certificate not configured' unless configured?
        authorize!(actor)

        bytes = payload.to_s.b
        key = load_key!
        cert = load_cert!
        assert_cert_usable!(cert)

        pkcs7 = OpenSSL::PKCS7.sign(cert, key, bytes, [], FLAGS)
        signed_at = Time.now.utc.iso8601
        result = Result.new(
          payload: bytes,
          signature_pem: pkcs7.to_pem,
          certificate_pem: cert.to_pem,
          certificate_fingerprint_sha256: fingerprint(cert),
          signer_subject: cert.subject.to_s,
          signed_at: signed_at,
          payload_sha256: Digest::SHA256.hexdigest(bytes),
          digest_algorithm: DIGEST
        )

        audit_sign!(purpose: purpose, actor: actor, result: result)
        result
      rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::PKey::PKeyError => e
        audit_failure!(purpose: purpose, actor: actor, error: e.class.name)
        raise Error, 'digital signature failed'
      end

      # Independent verification helper (also used by tests / rake).
      def verify(payload, signature_pem, certificate_pem: nil, trusted_certs: nil)
        bytes = payload.to_s.b
        p7 = OpenSSL::PKCS7.new(signature_pem)
        certs = Array(trusted_certs)
        if certificate_pem.present?
          certs << OpenSSL::X509::Certificate.new(certificate_pem)
        end
        store = OpenSSL::X509::Store.new
        certs.each { |c| store.add_cert(c) }
        # Self-signed lab certs: add certs as trusted anchors explicitly.
        p7.verify(certs, store, bytes, FLAGS)
      end

      def key_path
        ENV['FOREMAN_SIGNING_KEY_FILE'].presence
      end

      def cert_path
        ENV['FOREMAN_SIGNING_CERT_FILE'].presence
      end

      private

      def load_key!
        pem = File.read(key_path)
        raise NotConfigured, 'signing private key empty' if pem.blank?
        # Reject accidental reuse of ENCRYPTION_KEY material (hex blob).
        if pem.match?(/\A[0-9a-fA-F]{64}\z/)
          raise Error, 'signing key looks like ENCRYPTION_KEY; use an X.509 private key PEM'
        end
        OpenSSL::PKey.read(pem)
      end

      def load_cert!
        OpenSSL::X509::Certificate.new(File.read(cert_path))
      end

      def assert_cert_usable!(cert)
        now = Time.now.utc
        if cert.not_before && now < cert.not_before.utc
          raise InvalidCertificate, 'signing certificate not yet valid'
        end
        if cert.not_after && now > cert.not_after.utc
          raise InvalidCertificate, 'signing certificate expired'
        end
      end

      def fingerprint(cert)
        Digest::SHA256.hexdigest(cert.to_der)
      end

      def audit_sign!(purpose:, actor:, result:)
        return unless defined?(Foreman::SecurityEvent)

        Foreman::SecurityEvent.log(
          event: 'DIGITAL_SIGNATURE_CREATED',
          status: 'SUCCESS',
          actor: actor&.try(:login) || actor.to_s,
          target: purpose.to_s,
          details: "fp=#{result.certificate_fingerprint_sha256} sha256=#{result.payload_sha256} alg=#{DIGEST}"
        )
      end

      def audit_failure!(purpose:, actor:, error:)
        return unless defined?(Foreman::SecurityEvent)

        Foreman::SecurityEvent.log(
          event: 'DIGITAL_SIGNATURE_FAILED',
          status: 'FAILURE',
          actor: actor&.try(:login) || actor.to_s,
          target: purpose.to_s,
          details: "error=#{error}"
        )
      end
    end
  end
end
