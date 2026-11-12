# frozen_string_literal: true

# Account-level lockout for local (AuthSourceInternal) password authentication.
# Complements IP-based Foreman::BruteforceProtection; does not apply to LDAP/SSO/external auth.
module UserAccountLockout
  extend ActiveSupport::Concern

  # Snapshot of failed_login_attempts captured immediately before a successful
  # login resets lockout state (F-002). Used for post-login notification / history.
  attr_accessor :failed_attempts_before_login

  def account_locked?
    locked_until.present? && locked_until > Time.current.utc
  end

  # Clears an expired temporary lock so a new authentication attempt can proceed.
  def clear_expired_account_lock!
    return false unless locked_until.present?
    return false if locked_until > Time.current.utc

    logger.info("Account lock expired for user #{login} (id=#{id})")
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

    # Captured inside the lock after a successful commit of a new lockout transition.
    lockout_event = nil

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
      duration_minutes = Setting[:account_lockout_duration].to_i
      duration = duration_minutes.minutes

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
        lockout_event = {
          attempts: failed_login_attempts.to_i,
          attempts_limit: attempts_limit,
          duration_minutes: duration_minutes,
          locked_until: locked_until.utc,
        }
      end

      update_columns(
        failed_login_attempts: failed_login_attempts,
        failed_login_started_at: failed_login_started_at,
        locked_until: locked_until
      )
    end

    # Emit only after columns are committed; never for already-locked retries.
    # Logging/forwarding failures must not affect lockout enforcement.
    emit_account_lockout_security_event(lockout_event) if lockout_event
  end

  private

  # F-043: structured ACCOUNT_LOCKOUT on unlocked → locked transition only.
  # Target = locked account. Actor is not invented for anonymous failed logins
  # (the target login is not the attacker identity).
  def emit_account_lockout_security_event(meta)
    Foreman::SecurityEvent.log(
      event: 'ACCOUNT_LOCKOUT',
      status: 'LOCKED',
      level: :warn,
      actor: nil,
      target: login,
      operation: 'account.lockout',
      reason_code: 'failed_password_threshold',
      details: [
        "user_id=#{id}",
        "attempts=#{meta[:attempts]}",
        "limit=#{meta[:attempts_limit]}",
        "duration_minutes=#{meta[:duration_minutes]}",
        "locked_until=#{meta[:locked_until].utc.iso8601}",
        'source=UserAccountLockout',
      ].join(' ')
    )
  rescue StandardError => e
    logger.warn("ACCOUNT_LOCKOUT security event failed: #{e.class}") if defined?(logger)
  end
end
