# frozen_string_literal: true

module Foreman
  # Inventory and remediate Encryptable / EncryptValue fields that were stored
  # without the encrypted- prefix (typically written while ENCRYPTION_KEY was absent).
  #
  # Never logs secret values — only model name, record id, field, and outcome.
  class EncryptionLegacy
    Outcome = Struct.new(:model, :id, :field, :status, keyword_init: true)

    # Use leading :: so lookups inside the Foreman:: namespace do not miss
    # top-level Encryptable models (e.g. ::HttpProxy vs Foreman::HttpProxy).
    ENCRYPTABLE_TARGETS = [
      [-> { ::JwtSecret }, :token],
      [-> { ::ComputeResource }, :password],
      [-> { ::HttpProxy }, :password],
      [-> { ::AuthSourceLdap }, :account_password],
      [-> { ::KeyPair }, :secret],
      [-> { ::Nic::BMC }, :password],
      [-> { ::ForemanRegister::RegistrationFacet }, :jwt_secret],
    ].freeze

    def self.key_probe
      ComputeResource.new.encryption_key
    end

    def self.key_configured?
      key_probe.to_s.strip.present?
    end

    def initialize(dry_run: true, logger: Rails.logger)
      @dry_run = dry_run
      @logger = logger
      @outcomes = []
    end

    attr_reader :outcomes

    def inventory
      rows = []
      each_target do |klass, field|
        next unless klass.respond_to?(:table_exists?) && klass.table_exists?

        table = klass.table_name
        col = field.to_s
        prefix = EncryptValue::ENCRYPTION_PREFIX
        scope = klass.unscoped
        rows << {
          model: klass.name,
          field: field,
          total: scope.count,
          blank: scope.where(col => [nil, '']).count,
          encrypted: scope.where("#{table}.#{col} LIKE ?", "#{prefix}%").count,
          plaintext_candidates: candidate_scope(klass, field).count,
          candidate_ids: candidate_scope(klass, field).order(:id).limit(500).pluck(:id),
        }
      end
      rows.concat(settings_inventory)
      rows
    end

    def remediate!
      unless self.class.key_configured?
        raise Foreman::Exception.new(N_('ENCRYPTION_KEY is not configured; cannot remediate secrets'))
      end

      each_target do |klass, field|
        next unless klass.respond_to?(:table_exists?) && klass.table_exists?

        candidate_scope(klass, field).find_each do |record|
          @outcomes << remediate_record(record, field)
        end
      end
      remediate_encrypted_settings!
      @outcomes
    end

    def summary
      counts = Hash.new(0)
      @outcomes.each { |o| counts[o.status] += 1 }
      counts
    end

    private

    def each_target
      ENCRYPTABLE_TARGETS.each do |klass_proc, field|
        klass = klass_proc.call
        yield klass, field
      rescue NameError
        next
      end
    end

    def candidate_scope(klass, field)
      table = klass.table_name
      col = field.to_s
      prefix = EncryptValue::ENCRYPTION_PREFIX
      klass.unscoped.where.not(col => [nil, '']).where.not("#{table}.#{col} LIKE ?", "#{prefix}%")
    end

    def settings_inventory
      return [] unless defined?(Setting)

      encrypted = 0
      candidates = 0
      candidate_ids = []
      total = 0
      Setting.unscoped.find_each do |setting|
        next unless setting.encrypted?

        total += 1
        raw = setting.read_attribute(:value).to_s
        next if raw.blank?

        if raw.start_with?(EncryptValue::ENCRYPTION_PREFIX)
          encrypted += 1
        else
          candidates += 1
          candidate_ids << setting.id
        end
      end
      [{
        model: 'Setting(encrypted)',
        field: :value,
        total: total,
        blank: 0,
        encrypted: encrypted,
        plaintext_candidates: candidates,
        candidate_ids: candidate_ids.first(500),
      }]
    rescue StandardError => e
      @logger.warn("EncryptionLegacy settings inventory skipped (#{e.class})")
      []
    end

    def remediate_encrypted_settings!
      return unless defined?(Setting)

      Setting.unscoped.find_each do |setting|
        next unless setting.encrypted?

        raw = setting.read_attribute(:value).to_s
        next if raw.blank? || raw.start_with?(EncryptValue::ENCRYPTION_PREFIX)

        @outcomes << remediate_setting(setting)
      end
    end

    def remediate_setting(setting)
      model = 'Setting'
      field = :value
      if @dry_run
        log_outcome(model, setting.id, field, :would_encrypt)
        return Outcome.new(model: model, id: setting.id, field: field, status: :would_encrypt)
      end

      logical = setting.value
      setting.value = logical
      setting.save!
      setting.reload
      raw = setting.read_attribute(:value).to_s
      unless raw.start_with?(EncryptValue::ENCRYPTION_PREFIX)
        log_outcome(model, setting.id, field, :verify_failed)
        return Outcome.new(model: model, id: setting.id, field: field, status: :verify_failed)
      end

      log_outcome(model, setting.id, field, :encrypted)
      Outcome.new(model: model, id: setting.id, field: field, status: :encrypted)
    rescue StandardError => e
      @logger.warn("EncryptionLegacy Setting id=#{setting.id} failed (#{e.class})")
      Outcome.new(model: model, id: setting.id, field: field, status: :error)
    end

    def remediate_record(record, field)
      model = record.class.name
      raw = record.read_attribute(field).to_s
      if raw.blank?
        return Outcome.new(model: model, id: record.id, field: field, status: :skipped_blank)
      end
      if record.matches_prefix?(raw)
        return Outcome.new(model: model, id: record.id, field: field, status: :skipped_encrypted)
      end
      unless eligible_plaintext_candidate?(record, field, raw)
        log_outcome(model, record.id, field, :skipped_ineligible)
        return Outcome.new(model: model, id: record.id, field: field, status: :skipped_ineligible)
      end

      logical_before = record.public_send(field)

      if @dry_run
        log_outcome(model, record.id, field, :would_encrypt)
        return Outcome.new(model: model, id: record.id, field: field, status: :would_encrypt)
      end

      # Force dirty so Encryptable#encrypt_setters runs even if the plaintext is unchanged.
      # Skip validations: we are only changing at-rest encoding, not business attributes.
      # (JwtSecret uniqueness is unreliable while plaintext and ciphertext rows coexist.)
      record.write_attribute(field, raw)
      record.send("#{field}_will_change!")
      record.save!(validate: false)
      record.reload

      at_rest = record.read_attribute(field).to_s
      unless record.matches_prefix?(at_rest)
        log_outcome(model, record.id, field, :verify_failed)
        return Outcome.new(model: model, id: record.id, field: field, status: :verify_failed)
      end
      unless record.public_send(field) == logical_before
        log_outcome(model, record.id, field, :logical_mismatch)
        return Outcome.new(model: model, id: record.id, field: field, status: :logical_mismatch)
      end

      log_outcome(model, record.id, field, :encrypted)
      Outcome.new(model: model, id: record.id, field: field, status: :encrypted)
    rescue StandardError => e
      @logger.warn("EncryptionLegacy #{model} id=#{record.id} field=#{field} failed (#{e.class})")
      Outcome.new(model: model, id: record.id, field: field, status: :error)
    end

    # Do not treat every non-prefixed string as a credential. JwtSecret / registration
    # secrets are random base64; passwords are non-empty strings without the prefix.
    # Values that look like truncated ciphertext (contain '--' MessageEncryptor separator
    # but lack prefix) are left alone for operator review.
    def eligible_plaintext_candidate?(record, field, raw)
      return false if raw.start_with?(EncryptValue::ENCRYPTION_PREFIX)
      # Likely already MessageEncryptor material missing prefix — do not re-wrap.
      return false if raw.include?('--') && raw.match?(%r{\A[A-Za-z0-9+/=\n\-_]{20,}--[a-f0-9]{20,}\z}m)

      true
    end

    def log_outcome(model, id, field, status)
      @logger.info("EncryptionLegacy #{model}##{id}.#{field} => #{status}")
    end
  end
end
