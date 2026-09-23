# frozen_string_literal: true

module Foreman
  # Production HTTPS default for SETTINGS[:require_ssl].
  # Explicit FOREMAN_REQUIRE_SSL=true|false always wins via EnvSettingsLoader.
  # When the env key is unset in production, mandate require_ssl=true
  # (force_ssl + Secure session cookies). Lab/local stacks set
  # FOREMAN_REQUIRE_SSL=false intentionally.
  module SslDefaults
    module_function

    def apply!(settings, env:, rails_env:)
      return settings unless rails_env.to_s == 'production'
      return settings if env.key?('FOREMAN_REQUIRE_SSL')

      settings[:require_ssl] = true
      settings
    end
  end
end
