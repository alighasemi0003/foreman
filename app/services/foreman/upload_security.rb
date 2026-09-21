# frozen_string_literal: true

# Application-level upload/input safety helpers for Foreman's real surfaces.
# Intentionally small: size bounds, JPEG magic checks, PEM CA parsing, and
# download filename sanitization. Not a generic upload framework or AV scanner.
module Foreman
  module UploadSecurity
    # LDAP jpegPhoto avatars — profile thumbnails; keep conservative.
    MAX_AVATAR_BYTES = 100.kilobytes
    MIN_AVATAR_BYTES = 32

    # Provisioning / partition / report template text in DB.
    MAX_TEMPLATE_BYTES = 1.megabyte

    # Puppet/structured facts JSON can be multi-MB; bound memory growth.
    MAX_FACTS_BODY_BYTES = 10.megabytes

    # Config reports with logs are often larger than templates but same order.
    MAX_CONFIG_REPORT_BODY_BYTES = 10.megabytes

    # CA bundles (multiple PEMs) — below Mozilla store size with headroom.
    MAX_CACERT_BYTES = 256.kilobytes

    MAX_DOWNLOAD_FILENAME_LENGTH = 200

    JPEG_MAGIC = "\xFF\xD8\xFF".b.freeze
    JPEG_EOI = "\xFF\xD9".b.freeze
    PNG_MAGIC = "\x89PNG\r\n\x1A\n".b.freeze
    GIF_MAGIC = 'GIF8'.b.freeze
    PDF_MAGIC = '%PDF'.b.freeze
    ELF_MAGIC = "\x7FELF".b.freeze
    MZ_MAGIC = 'MZ'.b.freeze

    PEM_CERT_BLOCK = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m.freeze

    class InvalidCacert < StandardError; end

    module_function

    def within_byte_limit?(data, max_bytes)
      data.respond_to?(:bytesize) && data.bytesize <= max_bytes
    end

    # Valid LDAP jpegPhoto payload: JPEG SOI + EOI, size bounds, no foreign magic.
    def valid_jpeg_avatar?(bytes)
      return false if bytes.nil? || !bytes.respond_to?(:bytesize)
      return false if bytes.bytesize < MIN_AVATAR_BYTES || bytes.bytesize > MAX_AVATAR_BYTES

      binary = bytes.to_s.b
      return false unless binary.start_with?(JPEG_MAGIC)
      return false unless binary.include?(JPEG_EOI)
      return false if binary.start_with?(PNG_MAGIC, GIF_MAGIC, PDF_MAGIC, ELF_MAGIC, MZ_MAGIC)
      return false if looks_like_markup?(binary)

      true
    end

    def looks_like_markup?(binary)
      head = binary[0, 512].to_s.downcase
      head.include?('<html') || head.include?('<!doctype') ||
        head.include?('<svg') || head.include?('<?xml')
    end

    # Decode LDAP avatar input to binary with early size rejection.
    # Returns nil when input is empty, oversized, undecodable, or not a JPEG.
    def extract_avatar_binary(avatar)
      return nil if avatar.nil?

      if defined?(Net::BER::BerIdentifiedString) && avatar.instance_of?(Net::BER::BerIdentifiedString)
        binary = avatar.to_s.b
        return nil unless within_byte_limit?(binary, MAX_AVATAR_BYTES)
        return binary if valid_jpeg_avatar?(binary)

        return nil
      end

      encoded = avatar.to_s
      # Base64 expands ~4/3; reject oversized encoded input before decode.
      return nil if encoded.bytesize > ((MAX_AVATAR_BYTES * 4 / 3) + 64)

      binary = Base64.decode64(encoded).to_s.b
      return nil unless valid_jpeg_avatar?(binary)

      binary
    rescue ArgumentError
      nil
    end

    def validate_cacert!(pem)
      raise InvalidCacert, _('is too large') unless within_byte_limit?(pem, MAX_CACERT_BYTES)

      text = pem.to_s
      raise InvalidCacert, _('is not a valid CA certificate') if text.match?(/BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY/)

      blocks = text.scan(PEM_CERT_BLOCK)
      raise InvalidCacert, _('is not a valid CA certificate') if blocks.empty?

      blocks.each do |block|
        OpenSSL::X509::Certificate.new(block)
      end
      true
    rescue OpenSSL::X509::CertificateError
      raise InvalidCacert, _('is not a valid CA certificate')
    end

    def request_body_too_large?(request, limit)
      content_length = request.content_length
      if content_length.nil? && request.respond_to?(:get_header)
        header = request.get_header('CONTENT_LENGTH')
        content_length = header.to_i if header.present?
      end
      return true if content_length && content_length > limit

      # Fallback when Content-Length is absent/wrong but body is already buffered.
      if request.respond_to?(:raw_post)
        begin
          raw = request.raw_post
          return true if raw && raw.bytesize > limit
        rescue StandardError
          # Ignore rewind/unavailable body; Content-Length already checked.
        end
      end
      false
    end

    # Sanitize Content-Disposition filenames only (not storage paths).
    def safe_download_filename(name, default: 'download')
      return default.to_s if name.blank?

      # Drop directory components from either separator style.
      base = File.basename(name.to_s.tr('\\', '/'))
      # Strip controls and characters that break/smuggle Content-Disposition.
      base = base.gsub(/[[:cntrl:];"\\]/, '_')
      base = base.strip
      base = default.to_s if base.blank? || base == '/' || base.match?(/\A\.+\z/)
      if base.bytesize > MAX_DOWNLOAD_FILENAME_LENGTH
        ext = File.extname(base)
        stem = File.basename(base, ext)
        keep = MAX_DOWNLOAD_FILENAME_LENGTH - ext.bytesize
        keep = 1 if keep < 1
        base = stem.byteslice(0, keep).to_s + ext
      end
      base
    end
  end
end
