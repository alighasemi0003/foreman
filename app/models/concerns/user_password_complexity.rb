# frozen_string_literal: true

# Enforces local Foreman-managed password complexity.
# Applies only when a plaintext password is being set for an auth source that
# allows Foreman to manage passwords (AuthSourceInternal).
#
# Policy: length >= 8, at least one letter, one digit, and one special character.
# Special character = non-alphanumeric, non-whitespace (space alone does not qualify).
module UserPasswordComplexity
  extend ActiveSupport::Concern

  COMPLEXITY_ERROR = N_(
    "Complexity requirement not met. Length should be 8 or more and include: " \
    "1 letter, 1 number and 1 special character."
  )

  MINIMUM_LENGTH = 8

  included do
    validate :password_complexity
  end

  # Public for tests / documentation of policy.
  def self.compliant?(plaintext)
    return false if plaintext.blank?

    plaintext.length >= MINIMUM_LENGTH &&
      plaintext.match?(/[[:alpha:]]/) &&
      plaintext.match?(/[[:digit:]]/) &&
      plaintext.match?(/[^[:alnum:][:space:]]/)
  end

  private

  def password_complexity
    return if password.blank?
    return unless manage_password?

    return if UserPasswordComplexity.compliant?(password)

    errors.add(:password, _(COMPLEXITY_ERROR))
  end
end
