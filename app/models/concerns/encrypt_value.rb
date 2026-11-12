module EncryptValue
  ENCRYPTION_PREFIX = "encrypted-"

  def matches_prefix?(str)
    str.to_s.start_with? ENCRYPTION_PREFIX
  end

  # Native Foreman load order:
  # 1) ENCRYPTION_KEY environment variable
  # 2) ENCRYPTION_KEY_FILE path (Docker/secret mount; never commit the file)
  # 3) EncryptionKey::ENCRYPTION_KEY from config/initializers/encryption_key.rb
  def encryption_key
    return ENV['ENCRYPTION_KEY'] if ENV['ENCRYPTION_KEY'].present?

    file_key = encryption_key_from_file
    return file_key if file_key.present?

    return EncryptionKey::ENCRYPTION_KEY if defined? EncryptionKey::ENCRYPTION_KEY

    nil
  end

  def is_encryptable?(str)
    encryption_key.present? && str.present? && !matches_prefix?(str)
  end

  def is_decryptable?(str)
    encryption_key.present? && matches_prefix?(str)
  end

  def encrypt_field(str)
    return str if str.blank? || matches_prefix?(str)

    # Fail closed: never silently persist secrets as plaintext when encryption cannot succeed.
    unless encryption_key.present?
      puts_and_logs("ENCRYPTION_KEY is not configured; refusing to store secret plaintext")
      raise Foreman::Exception.new(N_("ENCRYPTION_KEY is not configured; cannot store secrets"))
    end

    begin
      # add prefix to encrypted string
      "#{ENCRYPTION_PREFIX}#{encryptor.encrypt_and_sign(str)}"
    rescue Foreman::Exception
      raise
    rescue StandardError => e
      # Log class only — never echo exception messages that might include secret material.
      unless defined?(@@encrypt_err_reported) && @@encrypt_err_reported
        puts_and_logs("At least one field encryption failed (#{e.class}); refusing plaintext storage")
        @@encrypt_err_reported = true
      end
      raise Foreman::Exception.new(N_("Secret encryption failed; cannot store secrets"))
    end
  end

  def decrypt_field(str)
    return str unless is_decryptable?(str)
    begin
      # remove prefix before decrypting string
      str_no_prefix = str.gsub(/^#{ENCRYPTION_PREFIX}/, "")
      str_decrypted = encryptor.decrypt_and_verify(str_no_prefix)
      str = str_decrypted
    rescue ActiveSupport::MessageVerifier::InvalidSignature
      puts_and_logs("At least one field decryption failed, check ENCRYPTION_KEY") unless defined?(@@decrypt_err_reported) && @@decrypt_err_reported
      @@decrypt_err_reported = true
    end
    str
  end

  def self.reset_warnings
    @@decrypt_err_reported = false
    @@encrypt_err_reported = false
  end

  private

  def encryption_key_from_file
    path = ENV['ENCRYPTION_KEY_FILE'].to_s
    return nil if path.blank?
    return nil unless File.file?(path) && File.readable?(path)

    File.read(path).to_s.strip.presence
  rescue Errno::ENOENT, Errno::EACCES => e
    puts_and_logs("ENCRYPTION_KEY_FILE unreadable (#{e.class})")
    nil
  end

  def puts_and_logs(msg, level = Logger::WARN)
    logger.add level, msg
    puts msg if Foreman.in_rake? && !Rails.env.test? && level >= Logger::WARN
  end

  def encryptor
    full_key = encryption_key

    # Pass a limited length encryption key as Ruby's OpenSSL bindings will either raise an
    # exception for a mis-sized key or it will be silently truncated.
    #
    # Pass a full length signature key though, so pre-existing encrypted data can still be verified
    # against a key that is longer than the necessary encryption key.
    ActiveSupport::MessageEncryptor.new(full_key[0, ActiveSupport::MessageEncryptor.key_len], full_key)
  end
end
