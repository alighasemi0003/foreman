# frozen_string_literal: true

# F-008: minimum character difference between current and new local passwords.
#
# Metric (adopted interpretation of audit requirement 15.4):
#   Unicode character Levenshtein edit distance (insert / delete / substitute)
#   of at least MINIMUM_EDIT_DISTANCE (4) between the prior plaintext password
#   and the candidate. Comparison is character-based (Ruby UTF-8 codepoints via
#   String#each_char), not byte-based.
#
# Availability constraint:
#   One-way password hashes cannot recover the prior plaintext. This check runs
#   only when +current_password+ is present in the request (self-service /
#   forced change / API self-update). Administrative resets without the prior
#   plaintext still enforce non-identity via hash comparison
#   (ensure_new_password_differs_from_current) and password history (F-009).
module UserPasswordSimilarity
  extend ActiveSupport::Concern

  MINIMUM_EDIT_DISTANCE = 4
  # Bound Levenshtein matrix size (O(n*m)) against oversized input abuse.
  MAX_COMPARE_CHARS = 256

  SIMILARITY_ERROR = N_(
    "The new password must differ from the current password by at least 4 characters."
  )

  included do
    # After verify_current_password and identity hash check; before prepare_password.
    before_validation :ensure_password_edit_distance,
                      if: :should_check_password_edit_distance?
  end

  # Public for tests / documentation.
  def self.edit_distance(left, right, max_chars: MAX_COMPARE_CHARS)
    a = left.to_s.each_char.take(max_chars)
    b = right.to_s.each_char.take(max_chars)
    n = a.length
    m = b.length
    return m if n.zero?
    return n if m.zero?

    # Two-row DP; early exit when every cell already exceeds the threshold is optional.
    prev = Array.new(m + 1) { |j| j }
    curr = Array.new(m + 1, 0)
    (1..n).each do |i|
      curr[0] = i
      (1..m).each do |j|
        cost = (a[i - 1] == b[j - 1]) ? 0 : 1
        curr[j] = [
          prev[j] + 1,      # deletion
          curr[j - 1] + 1, # insertion
          prev[j - 1] + cost, # substitution
        ].min
      end
      prev, curr = curr, prev
    end
    prev[m]
  end

  def self.sufficiently_different?(previous_plaintext, candidate_plaintext)
    return false if previous_plaintext.blank? || candidate_plaintext.blank?

    edit_distance(previous_plaintext, candidate_plaintext) >= MINIMUM_EDIT_DISTANCE
  end

  private

  def should_check_password_edit_distance?
    manage_password? &&
      !new_record? &&
      password.present? &&
      current_password.present? &&
      errors[:current_password].blank?
  end

  def ensure_password_edit_distance
    return if errors[:password].present? # e.g. already identical via hash check

    distance = UserPasswordSimilarity.edit_distance(current_password, password)
    return if distance >= MINIMUM_EDIT_DISTANCE

    errors.add(:password, _(SIMILARITY_ERROR))
  end
end
