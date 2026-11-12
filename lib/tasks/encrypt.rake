require 'foreman/util'

namespace :security do
  desc 'Generate new encryption key'
  task :generate_encryption_key do
    include Foreman::Util
    File.open(Rails.root.join('config', 'initializers', 'encryption_key.rb'), "w") do |fd|
      fd.write("# Be sure to restart your server when you modify this file.

# Your encryption key for encrypting and decrypting database fields.
# If you change this key, all encrypted data will NOT be able to be decrypted by Foreman!
# Make sure the key is at least 32 bytes such as SecureRandom.hex(20)

# You can use `rake security:generate_encryption_key` to regenerate this file.

module EncryptionKey
  ENCRYPTION_KEY = '#{secure_encryption_key}'
end
")
      puts "Encryption key generated in file config/initializers/encryption_key.rb"
      puts "Restart the server and then run rake db:compute_resources:encrypt"
    end
  end

  desc 'Check that a usable ENCRYPTION_KEY / ENCRYPTION_KEY_FILE / EncryptionKey is configured (no secret printed)'
  task :check_encryption_key => :environment do
    key = Foreman::EncryptionLegacy.key_probe
    if key.to_s.strip.empty?
      puts 'FAIL: ENCRYPTION_KEY is not configured'
      exit 1
    end
    puts "OK: encryption key present (length=#{key.length}, sha256_prefix=#{Digest::SHA256.hexdigest(key)[0, 8]})"
    path = ENV['ENCRYPTION_KEY_FILE'].to_s
    if path.present? && File.file?(path)
      mode = File.stat(path).mode & 0o777
      if (mode & 0o077) != 0
        puts "WARN: ENCRYPTION_KEY_FILE mode #{mode.to_s(8)} is readable by group/other; recommend 0600"
      else
        puts "OK: ENCRYPTION_KEY_FILE mode #{mode.to_s(8)}"
      end
    end
  end

  desc <<~END_DESC
    Inventory Encryptable fields that lack the encrypted- prefix (counts and ids only).

      rake security:encryption_inventory
  END_DESC
  task :encryption_inventory => :environment do
    inv = Foreman::EncryptionLegacy.new(dry_run: true).inventory
    total_enc = 0
    total_plain = 0
    inv.each do |row|
      total_enc += row[:encrypted]
      total_plain += row[:plaintext_candidates]
      puts "#{row[:model]}.#{row[:field]}: total=#{row[:total]} encrypted=#{row[:encrypted]} plaintext_candidates=#{row[:plaintext_candidates]} ids=#{row[:candidate_ids].inspect}"
    end
    puts "TOTAL encrypted=#{total_enc} plaintext_candidates=#{total_plain}"
    puts "KEY_CONFIGURED=#{Foreman::EncryptionLegacy.key_configured?}"
  end

  desc <<~END_DESC
    Re-encrypt legacy plaintext Encryptable secrets using the active ENCRYPTION_KEY.

    Defaults to dry-run. Real mutation requires CONFIRM=YES and a backup path.

      DRY_RUN=1 rake security:encrypt_legacy_secrets
      CONFIRM=YES BACKUP_PATH=/path/to/backup.sql.gz rake security:encrypt_legacy_secrets

    Preserves logical secret values (including JwtSecret HMAC material). Idempotent.
  END_DESC
  task :encrypt_legacy_secrets => :environment do
    # Real mutation only when both CONFIRM=YES and DRY_RUN=0 are set.
    dry_run = !(ENV['CONFIRM'] == 'YES' && ENV['DRY_RUN'] == '0')

    unless Foreman::EncryptionLegacy.key_configured?
      puts 'FAIL: ENCRYPTION_KEY is not configured'
      exit 1
    end

    if dry_run
      puts 'DRY-RUN: no database changes will be made (set CONFIRM=YES DRY_RUN=0 to apply)'
    else
      backup = ENV['BACKUP_PATH'].to_s
      if backup.empty? || !File.file?(backup)
        puts 'FAIL: refusing mutation without BACKUP_PATH pointing to an existing backup file'
        exit 1
      end
      age_hours = (Time.now - File.mtime(backup)) / 3600.0
      puts "BACKUP_PATH=#{backup} size=#{File.size(backup)} age_hours=#{age_hours.round(2)}"
      if age_hours > 24
        puts 'WARN: backup file is older than 24 hours; prefer a fresh pg_dump before mutation'
      end
    end

    migrator = Foreman::EncryptionLegacy.new(dry_run: dry_run)
    before = migrator.inventory
    before_plain = before.sum { |r| r[:plaintext_candidates] }
    puts "BEFORE plaintext_candidates=#{before_plain}"

    migrator.remediate!
    summary = migrator.summary
    summary.each { |status, count| puts "OUTCOME #{status}=#{count}" }

    after = Foreman::EncryptionLegacy.new(dry_run: true).inventory
    after_plain = after.sum { |r| r[:plaintext_candidates] }
    puts "AFTER plaintext_candidates=#{after_plain}"
    puts dry_run ? 'DRY-RUN complete' : 'Remediation complete'
  end
end

namespace :db do
  def modify_encryptable_fields(klass, action)
    klass.order(:id).each do |encryptable_resource|
      encryptable_resource.encryptable_fields.each do |field|
        str = encryptable_resource.read_attribute(field.to_sym)
        encryptable_resource.update_column(field.to_sym,
          encryptable_resource.send("#{action}_field", str))
      end
    end
  end

  desc <<~END_DESC
    Encrypt all passwords (compute resources, LDAP authentication sources) using
    the encryption key in config/initializers/encryption_key.rb.

    Plugins might enhance this task.

    This task is idempotent and it will just skip already encrypted passwords.
  END_DESC
  task :encrypt_all do
    Rake::Task['db:auth_sources_ldap:encrypt'].invoke
    Rake::Task['db:compute_resources:encrypt'].invoke
  end

  desc <<~END_DESC
    Decrypt all passwords (compute resources, LDAP authentication sources) using the encryption key
    in config/initializers/encryption_key.rb.

    Plugins might enhance this task.

    This task is idempotent and it will just skip already decrypted passwords.
  END_DESC
  task :decrypt_all do
    Rake::Task['db:auth_sources_ldap:decrypt'].invoke
    Rake::Task['db:compute_resources:decrypt'].invoke
  end

  namespace :auth_sources_ldap do
    desc "Encrypt LDAP authentication source fields"
    task :encrypt => :environment do
      modify_encryptable_fields(AuthSourceLdap, :encrypt)
    end

    desc "Decrypt LDAP authentication source fields"
    task :decrypt => :environment do
      modify_encryptable_fields(AuthSourceLdap, :decrypt)
    end
  end

  namespace :compute_resources do
    desc "Encrypt compute resource fields"
    task :encrypt => :environment do
      modify_encryptable_fields(ComputeResource, :encrypt)
    end

    desc "Decrypt compute resource fields"
    task :decrypt => :environment do
      modify_encryptable_fields(ComputeResource, :decrypt)
    end
  end
end
