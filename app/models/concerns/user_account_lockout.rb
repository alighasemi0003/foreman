# frozen_string_literal: true

# Account-level lockout for local (AuthSourceInternal) password authentication.
# Complements IP-based Foreman::BruteforceProtection; does not apply to LDAP/SSO/external auth.
module UserAccountLockout
  extend ActiveSupport::Concern

  def account_locked?
    locked_until.present? && locked_until > Time.current.utc
  end

  # Clears an expired temporary lock so a new authentication attempt can proceed.
  def clear_expired_account_lock!
    return false unless locked_until.present?
    return false if locked_until > Time.current.utc

    logger.info("Account lock expired for user #{login} (id=#{id})")
    Foreman::SecurityEvent.log(
      event: 'ACCOUNT_UNLOCKED',
      status: 'UNLOCKED',
      actor: login,
      ip: Foreman::SecurityEvent.current_ip,
      details: "id=#{id}"
    )
    reset_failed_login_state!
    true
  end

  def reset_failed_login_state!
    return unless has_attribute?(:failed_login_attempts)

    attrs = {
      failed_login_attempts: 0,
      failed_login_started_at: nil,
      locked_until: nil,
    }
    if persisted?
      update_columns(attrs)
    else
      assign_attributes(attrs)
    end
  end

  # Atomically records a failed local password authentication attempt and locks when threshold is reached.
  def register_failed_login!
    return unless internal?
    return unless has_attribute?(:failed_login_attempts)

    with_lock do
      reload
      now = Time.current.utc

      # Still locked: do not bump the counter again (login was rejected earlier).
      if locked_until.present? && locked_until > now
        return
      end

      # Expired lock: start a fresh failure window.
      if locked_until.present? && locked_until <= now
        self.failed_login_attempts = 0
        self.failed_login_started_at = nil
        self.locked_until = nil
      end

      window = Setting[:account_lockout_window].to_i.minutes
      attempts_limit = Setting[:account_lockout_attempts].to_i
      duration = Setting[:account_lockout_duration].to_i.minutes

      if failed_login_started_at.nil? || (now - failed_login_started_at.utc) > window
        self.failed_login_attempts = 1
        self.failed_login_started_at = now
        self.locked_until = nil
      else
        self.failed_login_attempts = failed_login_attempts.to_i + 1
      end

      if attempts_limit > 0 && failed_login_attempts >= attempts_limit
        self.locked_until = now + duration
        logger.warn("Account lockout threshold reached for user #{login} (id=#{id}), locked until #{locked_until.utc.iso8601}")
        Foreman::SecurityEvent.log(
          event: 'ACCOUNT_LOCKED',
          status: 'LOCKED',
          level: :warn,
          actor: login,
          ip: Foreman::SecurityEvent.current_ip,
          details: "id=#{id} locked_until=#{locked_until.utc.iso8601}"
        )
      end

      update_columns(
        failed_login_attempts: failed_login_attempts,
        failed_login_started_at: failed_login_started_at,
        locked_until: locked_until
      )
    end
  end
end
