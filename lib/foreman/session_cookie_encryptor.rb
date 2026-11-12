# frozen_string_literal: true

module Foreman
  # Authenticated encryption for the browser `_session_id` cookie value (F-017).
  #
  # The cookie still carries only the opaque public session id used by
  # ActiveRecord::SessionStore — never the session payload (that remains F-015).
  # MessageEncryptor (encrypt_and_sign) provides confidentiality + integrity.
  #
  # Wire format: FSC1:<MessageEncryptor ciphertext>
  # Legacy plain hex/public ids are rejected (controlled logout on upgrade).
  class SessionCookieEncryptor
    PREFIX = 'FSC1:'
    KEY_PURPOSE = 'foreman/session_cookie/v1'

    class << self
      def encrypt(public_session_id)
        return nil if public_session_id.blank?

        "#{PREFIX}#{encryptor.encrypt_and_sign(public_session_id.to_s)}"
      end

      # Returns the public session id, or nil if missing/tampered/wrong key/legacy.
      def decrypt(cookie_value)
        return nil if cookie_value.blank?

        str = cookie_value.to_s
        return nil unless str.start_with?(PREFIX)

        encryptor.decrypt_and_verify(str.delete_prefix(PREFIX))
      rescue ActiveSupport::MessageVerifier::InvalidSignature,
             ActiveSupport::MessageEncryptor::InvalidMessage,
             ArgumentError => e
        log_reject(e)
        nil
      end

      def encrypted?(cookie_value)
        cookie_value.to_s.start_with?(PREFIX)
      end

      def reset_encryptor!
        @encryptor = nil
      end

      private

      def encryptor
        @encryptor ||= build_encryptor
      end

      def build_encryptor
        secret_base = Rails.application.secret_key_base.to_s
        if secret_base.blank?
          raise Foreman::Exception.new(
            N_('secret_key_base is not configured; cannot encrypt session cookies')
          )
        end

        len = ActiveSupport::MessageEncryptor.key_len
        key = Rails.application.key_generator.generate_key(KEY_PURPOSE, len)
        ActiveSupport::MessageEncryptor.new(key)
      end

      def log_reject(error)
        return if defined?(@@reject_logged) && @@reject_logged

        Rails.logger.warn(
          "Encrypted session cookie rejected (#{error.class}); starting empty session"
        )
        @@reject_logged = true
      rescue StandardError
        nil
      end
    end
  end
end
