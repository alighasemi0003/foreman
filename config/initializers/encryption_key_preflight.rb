# frozen_string_literal: true

# Early detection of missing DB-field encryption configuration.
# Does not abort boot (migrations, recovery, and test must keep working).
# Secret writes already fail closed via EncryptValue#encrypt_field.
Rails.application.config.after_initialize do
  next if Foreman.in_setup_db_rake?
  next if Rails.env.test?

  begin
    key = ComputeResource.new.encryption_key
  rescue StandardError
    key = nil
  end

  if key.to_s.strip.empty?
    msg = 'ENCRYPTION_KEY is not configured; secret field writes will be rejected until a key is provided (see docs/encryption-key.md)'
    Rails.logger.error(msg)
    warn "[ERROR] #{msg}" if Rails.env.production?
  elsif ENV.key?('ENCRYPTION_KEY') && ENV['ENCRYPTION_KEY'].to_s.strip.empty? && ENV['ENCRYPTION_KEY_FILE'].to_s.strip.empty?
    # Compose often passes ENCRYPTION_KEY= when unset; fallthrough may still find EncryptionKey::ENCRYPTION_KEY.
    Rails.logger.info('ENCRYPTION_KEY env is empty; using ENCRYPTION_KEY_FILE or EncryptionKey constant if available')
  end
end
