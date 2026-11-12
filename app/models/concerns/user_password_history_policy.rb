# frozen_string_literal: true

# F-009: configurable prior-password reuse prevention for locally managed passwords.
#
# Setting[:password_history_length] = N
#   - N is the maximum number of *previous* password hash records retained/checked
#   - The *current* password is always rejected separately (ensure_new_password_differs_from_current)
#   - When current_password is supplied, F-008 also requires Levenshtein distance ≥ 4
#   - N = 0 disables historical checking (and prunes stored history on next successful change)
#   - Range 0..24 (upper bound limits expensive bcrypt/PBKDF2 comparisons)
#
# On successful local password change, the outgoing hash+salt is archived, then
# history is pruned to N. Increasing N keeps existing stored records (up to N).
# Decreasing N discards oldest excess on the next successful password update.
module UserPasswordHistoryPolicy
  extend ActiveSupport::Concern

  MAX_PASSWORD_HISTORY_LENGTH = 24
  HISTORY_REUSE_ERROR = N_('The new password cannot match a recently used password.')

  included do
    has_many :password_histories,
             class_name: 'UserPasswordHistory',
             dependent: :delete_all,
             inverse_of: :user

    # After current-password reuse check; before prepare_password mutates hash/salt.
    before_validation :ensure_password_not_in_history,
                      if: :should_check_password_history?

    before_save :stash_outgoing_password_for_history,
                if: :should_stash_outgoing_password_for_history?

    after_save :record_and_prune_password_history,
               if: :should_flush_password_history?
  end

  def password_history_length
    length = Setting[:password_history_length].to_i
    [[length, 0].max, MAX_PASSWORD_HISTORY_LENGTH].min
  rescue StandardError
    0
  end

  def password_matches_history?(plaintext)
    return false if plaintext.blank?
    return false unless manage_password?
    return false unless password_histories_table_ready?

    limit = password_history_length
    return false if limit <= 0

    password_histories.recent_first.limit(limit).any? { |row| row.matches_password?(plaintext) }
  end

  private

  def password_histories_table_ready?
    self.class.connection.data_source_exists?(:user_password_histories)
  rescue StandardError
    false
  end

  def should_check_password_history?
    manage_password? &&
      password.present? &&
      !new_record? &&
      password_history_length.positive? &&
      password_histories_table_ready?
  end

  def ensure_password_not_in_history
    return if errors[:password].present?
    return unless password_matches_history?(password)

    errors.add(:password, _(HISTORY_REUSE_ERROR))
  end

  def should_stash_outgoing_password_for_history?
    return false unless manage_password?
    return false unless password_histories_table_ready?
    return false if password.blank?
    return false unless will_save_change_to_password_hash?

    password_hash_in_database.present? && password_salt_in_database.present?
  end

  def stash_outgoing_password_for_history
    @outgoing_password_hash = password_hash_in_database
    @outgoing_password_salt = password_salt_in_database
  end

  def should_flush_password_history?
    return false unless manage_password?
    return false unless password_histories_table_ready?
    return false unless saved_change_to_password_hash?

    # Archive outgoing hash when present; when N=0 still prune any leftover rows.
    @outgoing_password_hash.present? || password_history_length <= 0
  end

  def record_and_prune_password_history
    hash = @outgoing_password_hash
    salt = @outgoing_password_salt
    @outgoing_password_hash = nil
    @outgoing_password_salt = nil

    with_lock do
      if hash.present? && salt.present? && password_history_length.positive?
        password_histories.create!(
          password_hash: hash,
          password_salt: salt,
          created_at: Time.now.utc
        )
      end
      prune_password_history!
    end
  rescue StandardError => e
    Foreman::Logging.exception(
      "Failed to record password history for user id=#{id}",
      e,
      :logger => 'app'
    )
    raise
  end

  def prune_password_history!
    keep = password_history_length
    scope = password_histories.recent_first
    overflow_ids = scope.offset(keep).limit(10_000).pluck(:id)
    return if overflow_ids.empty?

    password_histories.where(id: overflow_ids).delete_all
  end
end
