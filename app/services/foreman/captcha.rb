# frozen_string_literal: true

module Foreman
  # Interactive login anti-bot challenge (offline local provider).
  # Enable/disable via Administer → Settings → Authentication → Login CAPTCHA
  # (Setting[:captcha_enabled]). No external network dependency.
  # Applies only to password-form Local/LDAP login — not API, PAT, JWT,
  # extlogin/OIDC/REMOTE_USER, or reauthentication.
  module Captcha
    PROVIDER = 'local'
    DEFAULT_TTL_SECONDS = 5.minutes.to_i

    Result = Struct.new(:status, :message, :error_codes, keyword_init: true) do
      def success?
        status == :success
      end

      def failed?
        !success?
      end
    end

    module_function

    def enabled?
      !!Setting[:captcha_enabled]
    end

    def provider
      PROVIDER
    end

    def ttl_seconds
      configured = SETTINGS.dig(:captcha, :ttl_seconds).to_i
      configured.positive? ? configured : DEFAULT_TTL_SECONDS
    end

    # Safe props for LoginPage — never includes the answer.
    def frontend_config(session = nil)
      return { enabled: false } unless enabled?

      challenge = session ? Local.issue!(session) : { question: nil }
      {
        enabled: true,
        provider: provider,
        question: challenge[:question],
        refreshPath: '/users/captcha_challenge',
      }
    end

    def configuration_valid?
      true
    end

    # Verify a user response against the session-stored challenge.
    # Never logs the answer.
    def verify(response, session:)
      return Result.new(status: :success, message: 'captcha_disabled') unless enabled?

      Local.verify!(response, session: session)
    end
  end
end
