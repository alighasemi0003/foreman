# frozen_string_literal: true

# Successful interactive login history (F-001 / audit control 4).
# Records only confirmed UI/SSO session establishment — not API, PAT, JWT,
# reauthentication, or ordinary authenticated page loads.
#
# failed_attempts_before_login (F-002): unsuccessful local password attempts in
# the current account-lockout window immediately before successful login reset.
class UserLoginEvent < ApplicationRecord
  DEFAULT_RETENTION = 20
  MAX_RETENTION = 100

  # User has restrictive default scopes; validate via unscoped id existence.
  belongs_to :user, inverse_of: :login_events, optional: true

  validates :user_id, :logged_in_at, presence: true
  validate :user_must_exist
  validates :remote_ip, length: { maximum: 255 }, allow_nil: true
  validates :request_host, length: { maximum: 255 }, allow_nil: true
  validates :auth_method, length: { maximum: 64 }, allow_nil: true
  validates :auth_source_name, length: { maximum: 255 }, allow_nil: true
  validates :failed_attempts_before_login, numericality: { only_integer: true, greater_than_or_equal_to: 0 }

  scope :recent_first, -> { order(logged_in_at: :desc, id: :desc) }
  scope :for_user, ->(user) { where(user_id: user.is_a?(User) ? user.id : user) }

  # Persist one successful interactive login and enforce per-user retention.
  # Raises on create failure (same posture as Audit.manual_event! during login).
  # Retention cleanup failures are logged and do not roll back the insert.
  def self.record_successful_login!(user:, remote_ip:, request_host: nil, auth_method: nil, auth_source_name: nil,
                                     failed_attempts_before_login: nil)
    raise ArgumentError, 'user is required' unless user

    attempts = failed_attempts_before_login
    attempts = user.failed_attempts_before_login if attempts.nil?
    attempts = attempts.to_i
    attempts = 0 if attempts.negative?

    event = create!(
      user: user,
      logged_in_at: Time.now.utc,
      remote_ip: sanitize_field(remote_ip, 255),
      request_host: sanitize_field(request_host, 255),
      auth_method: sanitize_field(auth_method, 64),
      auth_source_name: sanitize_field(auth_source_name.presence || user.auth_source&.name, 255),
      failed_attempts_before_login: attempts
    )
    enforce_retention!(user)
    event
  end

  def self.retention_limit
    limit = Setting[:login_history_limit] rescue DEFAULT_RETENTION
    limit = DEFAULT_RETENTION if limit.blank?
    [[Integer(limit), 1].max, MAX_RETENTION].min
  rescue ArgumentError, TypeError
    DEFAULT_RETENTION
  end

  def self.enforce_retention!(user)
    keep = retention_limit
    scope = for_user(user).recent_first
    overflow_ids = scope.offset(keep).limit(10_000).pluck(:id)
    return if overflow_ids.empty?

    where(id: overflow_ids).delete_all
  rescue StandardError => e
    Foreman::Logging.exception(
      "Failed to enforce login history retention for user id=#{user.id}",
      e,
      :logger => 'app'
    )
  end

  def self.sanitize_field(value, max_len)
    return nil if value.nil?

    value.to_s.gsub(/[\x00-\x1f\x7f]/, ' ').strip.truncate(max_len).presence
  end
  private_class_method :sanitize_field

  def user_must_exist
    return if user_id.blank?
    return if User.unscoped.exists?(id: user_id)

    errors.add(:user_id, :invalid)
  end
end
