# frozen_string_literal: true

require 'base64'

module Foreman
  module SessionStore
    # Authenticated encryption wrapper for ActiveRecord::SessionStore payloads (F-015).
    #
    # Wire formats:
    #   ARSESS1:<MessageEncryptor ciphertext>  — current (encrypt_and_sign)
    #   BAh...                                 — legacy Base64(Marshal) plaintext (read-only)
    #
    # New writes always use ARSESS1. Legacy rows remain readable until the next
    # session save rewrites them encrypted. Tampered/undecryptable payloads
    # yield nil so Rack starts a fresh empty session (safe logout).
    #
    # Key material is derived from secret_key_base via KeyGenerator with a
    # dedicated purpose string — separate from EncryptValue ENCRYPTION_KEY.
    class EncryptedMarshalSerializer
      PREFIX = 'ARSESS1:'
      LEGACY_MARSHAL_SIGNATURE = 'BAh'
      KEY_PURPOSE = 'foreman/active_record_session_store/v1'

      class << self
        def dump(value)
          return nil if value.nil?

          plain = ::Base64.strict_encode64(Marshal.dump(value))
          "#{PREFIX}#{encryptor.encrypt_and_sign(plain)}"
        end

        def load(value)
          return nil if value.blank?

          str = value.to_s
          if str.start_with?(PREFIX)
            load_encrypted(str.delete_prefix(PREFIX))
          elsif legacy_marshal?(str)
            load_legacy_marshal(str)
          else
            nil
          end
        rescue StandardError => e
          log_load_failure(e)
          nil
        end

        def encrypted_payload?(value)
          value.to_s.start_with?(PREFIX)
        end

        def legacy_payload?(value)
          legacy_marshal?(value.to_s)
        end

        # Test helper — clear cached encryptor after secret_key_base changes.
        def reset_encryptor!
          @encryptor = nil
        end

        private

        def legacy_marshal?(str)
          str.start_with?(LEGACY_MARSHAL_SIGNATURE)
        end

        def load_encrypted(ciphertext)
          plain = encryptor.decrypt_and_verify(ciphertext)
          Marshal.load(::Base64.decode64(plain))
        end

        def load_legacy_marshal(str)
          Marshal.load(::Base64.decode64(str))
        end

        def encryptor
          @encryptor ||= build_encryptor
        end

        def build_encryptor
          secret_base = Rails.application.secret_key_base.to_s
          if secret_base.blank?
            raise Foreman::Exception.new(
              N_('secret_key_base is not configured; cannot encrypt session payloads')
            )
          end

          len = ActiveSupport::MessageEncryptor.key_len
          key = Rails.application.key_generator.generate_key(KEY_PURPOSE, len)
          # encrypt_and_sign => confidentiality + HMAC integrity (aes-256-cbc + verifier
          # while use_authenticated_message_encryption is false in this app).
          ActiveSupport::MessageEncryptor.new(key)
        end

        def log_load_failure(error)
          return if defined?(@@load_err_reported) && @@load_err_reported

          Rails.logger.warn(
            "Encrypted session payload could not be loaded (#{error.class}); starting empty session"
          )
          @@load_err_reported = true
        rescue StandardError
          nil
        end
      end
    end
  end
end
