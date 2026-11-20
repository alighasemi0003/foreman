# frozen_string_literal: true

# Secure-by-default baseline for Foreman 5.0 security-hardening installs.
#
# Code defaults in SettingManager cover nil DB values. This service also
# persists the approved baseline on first install (seed) and offers an
# explicit dry-run/apply path for existing databases (rake security:secure_defaults).
module Foreman
  class SecureDefaults
    BASELINE_ID = '5.0-secure'
    BASELINE_SETTING = 'security_hardening_baseline'

    # name => approved first-install value
    BASELINE = {
      'captcha_enabled' => true,
      'password_max_age' => 90,
      'idle_timeout' => 30,
      'password_history_length' => 5,
      'login_history_limit' => 20,
      'account_lockout_attempts' => 5,
      'account_lockout_window' => 15,
      'account_lockout_duration' => 30,
      'http_rate_limit_enabled' => true,
      'http_rate_limit_fail_closed' => true,
      'output_classification_enabled' => true,
      'reauthentication_window_minutes' => 5,
      'require_reauth_settings_reauthentication_policy' => true,
      'require_reauth_settings_oauth_credentials' => true,
      'require_reauth_users_set_admin' => true,
      'require_reauth_users_set_disabled' => true,
      'require_reauth_users_impersonate' => true,
      'require_reauth_auth_sources_update' => true,
      'require_reauth_users_destroy' => true,
      'require_reauth_users_change_password' => true,
      'require_reauth_users_change_roles' => true,
      'require_reauth_auth_sources_create' => true,
      'require_reauth_auth_sources_destroy' => true,
      'require_reauth_users_terminate_sessions' => true,
      'require_reauth_users_invalidate_jwt' => true,
      'require_reauth_users_create' => true,
      'require_reauth_personal_access_tokens_create' => true,
      'require_reauth_personal_access_tokens_revoke' => true,
      'require_reauth_ssh_keys_create' => true,
      'require_reauth_ssh_keys_destroy' => true,
      'require_reauth_registration_commands_create' => true,
      'require_reauth_key_pairs_download' => true,
      'require_reauth_key_pairs_recreate' => true,
      'require_reauth_key_pairs_destroy' => true,
      'require_reauth_hosts_console' => true,
      'require_reauth_compute_resources_vms_console' => true,
    }.freeze

    Change = Struct.new(:name, :current, :proposed, :action, keyword_init: true)

    class << self
      def baseline_id
        BASELINE_ID
      end

      def baseline_applied?
        Setting[BASELINE_SETTING].to_s == BASELINE_ID
      rescue StandardError
        false
      end

      # True only for empty / pre-admin databases that have not recorded a baseline.
      def first_install?
        return false if baseline_applied?
        return false unless settings_table_ready?

        User.unscoped.only_admin.except_hidden.none?
      rescue StandardError
        false
      end

      def skip_via_env?
        %w[0 false no skip].include?(ENV.fetch('FOREMAN_APPLY_SECURE_DEFAULTS', 'true').to_s.downcase)
      end

      def plan(force: false)
        changes = []
        BASELINE.each do |name, proposed|
          next unless setting_defined?(name)

          current = current_value(name)
          action = if values_equal?(current, proposed)
                     :unchanged
                   elsif force || current.nil? || at_legacy_insecure_default?(name, current)
                     :update
                   else
                     :skip_custom
                   end
          changes << Change.new(name: name, current: current, proposed: proposed, action: action)
        end
        changes
      end

      # Seed / first-boot: apply only on genuine first install.
      def apply_first_install!
        return { status: :skipped, reason: 'FOREMAN_APPLY_SECURE_DEFAULTS disabled' } if skip_via_env?
        return { status: :skipped, reason: 'baseline already applied' } if baseline_applied?
        return { status: :skipped, reason: 'not a first install (interactive admin exists)' } unless first_install?

        apply!(force: true, set_baseline: true)
      end

      # Explicit operator path for existing databases.
      def apply!(force: false, set_baseline: true, dry_run: false)
        raise 'Settings registry not ready' unless settings_table_ready?

        changes = plan(force: force)
        applied = []
        skipped = []

        changes.each do |change|
          if change.action == :update
            unless dry_run
              Setting[change.name] = change.proposed
            end
            applied << change
          else
            skipped << change
          end
        end

        if set_baseline && !dry_run && setting_defined?(BASELINE_SETTING)
          Setting[BASELINE_SETTING] = BASELINE_ID
        end

        {
          status: dry_run ? :dry_run : :applied,
          baseline: BASELINE_ID,
          applied: applied,
          skipped: skipped,
        }
      end

      def report_lines(result)
        lines = ["status=#{result[:status]} baseline=#{result[:baseline]}"]
        Array(result[:applied]).each do |c|
          lines << "apply #{c.name}: #{c.current.inspect} -> #{c.proposed.inspect}"
        end
        Array(result[:skipped]).each do |c|
          lines << "skip #{c.name}: current=#{c.current.inspect} action=#{c.action}"
        end
        lines << "reason=#{result[:reason]}" if result[:reason]
        lines
      end

      private

      def settings_table_ready?
        ActiveRecord::Base.connection.data_source_exists?(:settings) &&
          Foreman.settings.ready?
      rescue StandardError
        false
      end

      def setting_defined?(name)
        Foreman.settings.find(name).present?
      rescue StandardError
        false
      end

      def current_value(name)
        Setting[name]
      rescue StandardError
        nil
      end

      def values_equal?(a, b)
        return true if a == b
        if [true, false].include?(b) || [true, false].include?(a)
          return ActiveModel::Type::Boolean.new.cast(a) == ActiveModel::Type::Boolean.new.cast(b)
        end
        a.to_s == b.to_s
      rescue StandardError
        a == b
      end

      # Values that historically shipped insecure and are safe to upgrade automatically
      # when an operator runs secure_defaults without --force for every key.
      def at_legacy_insecure_default?(name, current)
        case name
        when 'captcha_enabled'
          current == false
        when 'password_max_age'
          current.to_i == 0
        when 'idle_timeout'
          current.to_i == 60
        when 'http_rate_limit_fail_closed'
          current == false
        else
          false
        end
      end
    end
  end
end
