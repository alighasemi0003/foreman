# frozen_string_literal: true

module Foreman
  module Reauthentication
    # Verifies credentials for step-up without creating a login session or LDAP side effects.
    class Verifier
      Result = Struct.new(:status, :message, keyword_init: true)

      def initialize(actor:, password:, request_ip:)
        @actor = actor
        @password = password.to_s
        @request_ip = request_ip
      end

      def call
        return Result.new(status: :authentication_failed, message: _('Authentication failed')) if @actor.nil?
        return Result.new(status: :authentication_failed, message: _('Authentication failed')) if @password.blank?

        bruteforce = Foreman::BruteforceProtection.new(request_ip: @request_ip)
        if bruteforce.bruteforce_attempt?
          bruteforce.log_bruteforce
          return Result.new(status: :rate_limited, message: _('Too many failed login attempts from your IP. Please try again later.'))
        end

        if @actor.internal?
          verify_local(bruteforce)
        elsif @actor.auth_source.is_a?(AuthSourceLdap)
          verify_ldap(bruteforce)
        else
          Result.new(status: :reauthentication_unsupported, message: _('Re-authentication is not supported for this authentication source.'))
        end
      end

      private

      def verify_local(bruteforce)
        @actor.clear_expired_account_lock! if @actor.respond_to?(:clear_expired_account_lock!)
        if @actor.account_locked?
          return Result.new(status: :account_locked, message: _('Authentication failed'))
        end

        if @actor.matching_password?(@password)
          @actor.reset_failed_login_state! if @actor.respond_to?(:reset_failed_login_state!)
          Result.new(status: :success, message: _('Re-authentication successful'))
        else
          @actor.register_failed_login! if @actor.respond_to?(:register_failed_login!)
          bruteforce.count_login_failure
          if @actor.account_locked?
            Result.new(status: :account_locked, message: _('Authentication failed'))
          else
            Result.new(status: :authentication_failed, message: _('Authentication failed'))
          end
        end
      end

      def verify_ldap(bruteforce)
        attrs = @actor.auth_source.authenticate(@actor.login, @password)
        if attrs
          # Intentionally discard attrs — do not update user or sync groups.
          Result.new(status: :success, message: _('Re-authentication successful'))
        else
          bruteforce.count_login_failure
          Result.new(status: :authentication_failed, message: _('Authentication failed'))
        end
      rescue Foreman::LdapException => e
        Foreman::Logging.exception('LDAP re-authentication failed', e, level: :warn)
        bruteforce.count_login_failure
        Result.new(status: :authentication_failed, message: _('Authentication failed'))
      rescue Net::LDAP::Error, Timeout::Error, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
        Foreman::Logging.exception('LDAP re-authentication connection error', e, level: :warn)
        bruteforce.count_login_failure
        Result.new(status: :authentication_failed, message: _('Authentication failed'))
      end
    end
  end
end
