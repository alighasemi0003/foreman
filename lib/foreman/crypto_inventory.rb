# frozen_string_literal: true

require 'json'
require 'openssl'
require 'tempfile'
require 'open3'

# F-024: read-only cryptographic inventory and optional isolated FIPS-provider probe.
# Never enables host/sysctl FIPS. Never rotates keys or rewrites ciphertext.
module Foreman
  module CryptoInventory
    module_function

    def report
      {
        task: 'F-024',
        generated_at: Time.now.utc.xmlschema,
        openssl: openssl_state,
        application: application_crypto,
        fips_compliance_claim: 'NOT_CLAIMED',
        notes: [
          'Algorithm presence is not FIPS module validation.',
          'Organizational approved policy was not supplied with this assessment.',
          'See docs/fips-cryptography-assessment.md',
        ],
      }
    end

    def openssl_state
      providers = []
      begin
        # OpenSSL::Provider available on OpenSSL 3 Ruby bindings
        if defined?(OpenSSL::Provider)
          OpenSSL::Provider.providers.each do |p|
            providers << { name: p.name, status: (p.inspect rescue 'unknown') }
          end
        end
      rescue StandardError => e
        providers << { error: "#{e.class}: #{e.message}" }
      end

      {
        openssl_version: OpenSSL::OPENSSL_VERSION,
        openssl_library_version: (OpenSSL::OPENSSL_LIBRARY_VERSION rescue nil),
        fips_mode: (OpenSSL.fips_mode rescue nil),
        fips_mode_writable: OpenSSL.respond_to?(:fips_mode=),
        providers: providers,
        crypto_policy: read_crypto_policy,
        md5_available: (Foreman::Fips.md5_available? rescue nil),
        message_encryptor_default_cipher: (ActiveSupport::MessageEncryptor.default_cipher rescue nil),
      }
    end

    def application_crypto
      {
        password_hash_setting: (Setting[:password_hash] rescue nil),
        password_new_algorithm: (Foreman::PasswordHash.algorithm_for_new_passwords rescue nil),
        password_approved_for_new: Foreman::PasswordHash::APPROVED_FOR_NEW,
        jwt_algorithm: (JwtToken::ALGORITHM rescue 'HS256'),
        encrypt_value: 'MessageEncryptor encrypt_and_sign (aes-256-cbc + HMAC when authenticated message encryption disabled)',
        session_payload: 'ARSESS1 MessageEncryptor (F-015)',
        session_cookie: 'FSC1 MessageEncryptor (F-017)',
        use_authenticated_message_encryption: Rails.application.config.active_support.use_authenticated_message_encryption,
        password_crypt_algorithms: (PasswordCrypt::ALGORITHMS.keys rescue []),
        password_crypt_default: (PasswordCrypt::DEFAULT_HASH_ALGORHITHM rescue nil),
        vnc_des: 'Foreman::Console::VncDes pure-Ruby DES (RFB protocol)',
        key_pair_export_cipher: 'aes-256-cbc',
        encryption_key_configured: encryption_key_present?,
      }
    end

    def encryption_key_present?
      return true if ENV['ENCRYPTION_KEY'].to_s.strip.present?
      path = ENV['ENCRYPTION_KEY_FILE'].to_s
      return true if path.present? && File.file?(path) && File.readable?(path)
      defined?(EncryptionKey::ENCRYPTION_KEY) && EncryptionKey::ENCRYPTION_KEY.to_s.strip.present?
    rescue StandardError
      false
    end

    def read_crypto_policy
      path = '/etc/crypto-policies/config'
      return File.read(path).to_s.strip if File.readable?(path)

      nil
    rescue StandardError
      nil
    end

    # Spawns a child ruby with a temporary OPENSSL_CONF that activates the fips
    # provider alongside default. Does not modify the parent process or host.
    def isolated_fips_provider_probe
      conf = Tempfile.new(['foreman-f024-fips', '.cnf'])
      conf.write(<<~CNF)
        openssl_conf = openssl_init
        [openssl_init]
        providers = provider_sect
        [provider_sect]
        fips = fips_sect
        default = default_sect
        [fips_sect]
        activate = 1
        [default_sect]
        activate = 1
      CNF
      conf.flush

      script = <<~'RUBY'
        require 'openssl'
        require 'json'
        result = { parent_fips_untouched: true }
        begin
          OpenSSL.fips_mode = true
          result[:fips_mode] = OpenSSL.fips_mode
        rescue StandardError => e
          result[:fips_mode_error] = "#{e.class}: #{e.message}"
        end
        begin
          c = OpenSSL::Cipher.new('aes-256-cbc')
          c.encrypt
          c.random_key
          c.random_iv
          c.update('f024') + c.final
          result[:aes_256_cbc] = 'ok'
        rescue StandardError => e
          result[:aes_256_cbc] = "#{e.class}: #{e.message}"
        end
        begin
          OpenSSL::Cipher.new('DES-ECB')
          result[:des_ecb] = 'available'
        rescue StandardError => e
          result[:des_ecb] = "#{e.class}: #{e.message}"
        end
        begin
          OpenSSL::Digest::MD5.hexdigest('x')
          result[:md5] = 'ok'
        rescue StandardError => e
          result[:md5] = "#{e.class}: #{e.message}"
        end
        begin
          OpenSSL::Digest::SHA1.hexdigest('x')
          result[:sha1] = 'ok'
        rescue StandardError => e
          result[:sha1] = "#{e.class}: #{e.message}"
        end
        begin
          OpenSSL::Digest::SHA256.hexdigest('x')
          result[:sha256] = 'ok'
        rescue StandardError => e
          result[:sha256] = "#{e.class}: #{e.message}"
        end
        puts JSON.generate(result)
      RUBY

      env = ENV.to_h.merge('OPENSSL_CONF' => conf.path)
      stdout, stderr, status = Open3.capture3(env, RbConfig.ruby, '-e', script)
      parsed = JSON.parse(stdout) rescue { parse_error: stdout, stderr: stderr }
      {
        probe: 'isolated_subprocess_OPENSSL_CONF',
        exitstatus: status.exitstatus,
        stderr: stderr.to_s.lines.last(5),
        result: parsed,
        warning: 'This does not enable host FIPS or validate a CMVP module in production.',
      }
    ensure
      conf.close!
    end
  end
end
