# frozen_string_literal: true

# First-install security baseline (CAPTCHA, password aging, idle timeout, etc.).
# Runs after bcrypt calibration seed and before interactive admin seed so the
# bootstrap admin receives password_changed_at under the aging policy without
# an immediate lockout loop.
#
# Existing databases with interactive admins are never modified here.
# Operators upgrade those explicitly: rake security:secure_defaults APPLY=1

unless defined?(Foreman::SecureDefaults)
  Rails.logger.warn('Skipping secure defaults seed — Foreman::SecureDefaults not loaded')
  return
end

begin
  result = Foreman::SecureDefaults.apply_first_install!
  Foreman::SecureDefaults.report_lines(result).each do |line|
    puts "[secure_defaults] #{line}" unless Rails.env.test?
    Rails.logger.info("[secure_defaults] #{line}")
  end
rescue StandardError => e
  Rails.logger.warn("[secure_defaults] skipped: #{e.class}: #{e.message}")
  puts "[secure_defaults] skipped: #{e.class}: #{e.message}" unless Rails.env.test?
end
