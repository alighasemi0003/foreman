# frozen_string_literal: true

# Prior local password verification material (F-009).
# Stores only hash + salt compatible with Foreman::PasswordHash — never plaintext.
class UserPasswordHistory < ApplicationRecord
  belongs_to :user, inverse_of: :password_histories

  validates :user_id, :password_hash, :password_salt, :created_at, presence: true

  scope :recent_first, -> { order(created_at: :desc, id: :desc) }
  scope :for_user, ->(user) { where(user_id: user.is_a?(User) ? user.id : user) }

  # Verify a candidate plaintext against this historical record's salt/hash.
  def matches_password?(plaintext)
    return false if plaintext.nil? || password_hash.blank? || password_salt.blank?

    type = Foreman::PasswordHash.detect_implementation(password_salt)
    computed = Foreman::PasswordHash.new(type).hash_secret(plaintext, password_salt)
    return false if computed.blank? || computed.bytesize != password_hash.bytesize

    ActiveSupport::SecurityUtils.secure_compare(computed, password_hash)
  rescue StandardError
    false
  end
end
