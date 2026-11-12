# frozen_string_literal: true

# F-007: configurable maximum age for locally managed passwords.
# Expiration reuses password_change_required enforcement (UI gate + session logout).
module UserPasswordExpiration
  extend ActiveSupport::Concern

  # Upper bound for Setting[:password_max_age] (days).
  MAX_PASSWORD_AGE_DAYS = 3650

  included do
    before_save :assign_password_changed_at, if: :should_assign_password_changed_at?
  end

  # Override AR boolean predicate so expiration shares the forced-change gate.
  def password_change_required?
    return false unless manage_password?
    return true if self[:password_change_required]

    password_expired?
  end

  # True when local password age exceeds Setting[:password_max_age] (days).
  # 0 / blank setting disables expiration. External/LDAP users are never expired here.
  def password_expired?
    return false unless manage_password?
    return false unless has_attribute?(:password_changed_at)

    max_age = password_max_age_days
    return false if max_age <= 0

    # Fail closed for local users missing a timestamp when policy is enabled
    # (migration backfills existing internals; new users stamp on password set).
    return true if password_changed_at.blank?

    Time.now.utc >= password_changed_at.utc + max_age.days
  end

  def password_max_age_days
    Setting[:password_max_age].to_i
  rescue StandardError
    0
  end

  private

  def should_assign_password_changed_at?
    return false unless has_attribute?(:password_changed_at)
    return false unless manage_password?
    return false if password.blank?

    will_save_change_to_password_hash?
  end

  def assign_password_changed_at
    self.password_changed_at = Time.now.utc
  end
end
