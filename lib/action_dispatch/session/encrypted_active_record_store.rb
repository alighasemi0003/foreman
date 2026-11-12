# frozen_string_literal: true

require 'action_dispatch/session/active_record_store'
require 'foreman/session_cookie_encryptor'

module ActionDispatch
  module Session
    # ActiveRecord session store that wraps the browser cookie value with
    # authenticated encryption (F-017) while preserving server-side lookup.
    class EncryptedActiveRecordStore < ActiveRecordStore
      private

      # Decrypt cookie → public sid → Rack::Session::SessionId (private_id for DB).
      def extract_session_id(req)
        raw = req.cookies[@key]
        return nil if raw.blank?

        public_id = Foreman::SessionCookieEncryptor.decrypt(raw)
        return nil if public_id.blank?

        ::Rack::Session::SessionId.new(public_id)
      end

      # Encrypt public sid before ActionDispatch::Cookies writes Set-Cookie.
      def set_cookie(request, _response, cookie)
        options = cookie.dup
        plain = options[:value]
        options[:value] = Foreman::SessionCookieEncryptor.encrypt(plain)
        # Non-persistent: do not add expires/max_age here; session_options control that.
        request.cookie_jar[@key] = options
      end
    end
  end
end
