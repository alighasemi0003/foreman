# frozen_string_literal: true

module Foreman
  # Interactive login anti-bot challenge (Cloudflare Turnstile).
  # Applies only to password-form Local/LDAP login — not API, PAT, JWT,
  # extlogin/OIDC/REMOTE_USER, or reauthentication.
  module Captcha
    TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com'
    TURNSTILE_SITEVERIFY_URL = "#{TURNSTILE_ORIGIN}/turnstile/v0/siteverify".freeze
    SUPPORTED_PROVIDERS = %w[turnstile].freeze

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
      !!SETTINGS.dig(:captcha, :enabled)
    end

    def provider
      (SETTINGS.dig(:captcha, :provider).presence || 'turnstile').to_s.downcase
    end

    def site_key
      SETTINGS.dig(:captcha, :turnstile, :site_key).to_s.presence
    end

    def secret_key
      SETTINGS.dig(:captcha, :turnstile, :secret_key).to_s.presence
    end

    # Safe props for LoginPage / HTML bootstrap — never includes secret.
    def frontend_config
      return { enabled: false } unless enabled?

      {
        enabled: true,
        provider: provider,
        siteKey: site_key,
      }
    end

    def configuration_valid?
      return true unless enabled?
      return false unless SUPPORTED_PROVIDERS.include?(provider)
      return false if site_key.blank? || secret_key.blank?

      true
    end

    # Verify a challenge token. Never logs the token or secret.
    def verify(response_token, remote_ip: nil)
      return Result.new(status: :success, message: 'captcha_disabled') unless enabled?

      unless configuration_valid?
        Rails.logger.error('[Captcha] enabled but configuration is invalid (provider/keys)')
        return Result.new(
          status: :configuration_error,
          message: 'captcha_configuration_error'
        )
      end

      token = response_token.to_s.strip
      if token.blank?
        return Result.new(status: :failed, message: 'captcha_missing')
      end

      case provider
      when 'turnstile'
        TurnstileVerifier.new.verify(token, remote_ip: remote_ip)
      else
        Rails.logger.error("[Captcha] unsupported provider=#{provider}")
        Result.new(status: :configuration_error, message: 'captcha_configuration_error')
      end
    end
  end
end
