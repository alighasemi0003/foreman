# frozen_string_literal: true

module Foreman
  module SecurityEvent
    # Builds the centralized security-event JSON schema (F-041).
    # Never include secrets — sanitize and scrub known sensitive tokens.
    module Payload
      SOURCE_SERVICE = 'foreman'
      EVENT_TYPE = 'security'

      SENSITIVE_SUBSTRINGS = %w[
        password passwd passphrase secret token jwt pat bearer
        authorization cookie session_id sessionid private_key
        encryption_key api_key captcha
      ].freeze

      module_function

      def build(event:, status:, actor: nil, actor_id: nil, target: nil, ip: nil,
                details: nil, operation: nil, reason_code: nil, request_id: nil)
        {
          'ts' => Time.now.utc.iso8601(3),
          'event_type' => EVENT_TYPE,
          'event_id' => event.to_s,
          'status' => status.to_s,
          'actor' => blank_to_nil(Foreman::SecurityEvent.sanitize(actor)),
          'actor_id' => actor_id.presence&.to_i,
          'target' => blank_to_nil(Foreman::SecurityEvent.sanitize(target)),
          'client_ip' => blank_to_nil(Foreman::SecurityEvent.sanitize(ip)),
          'request_id' => blank_to_nil(request_id),
          'operation' => blank_to_nil(Foreman::SecurityEvent.sanitize(operation)),
          'reason_code' => blank_to_nil(Foreman::SecurityEvent.sanitize(reason_code)),
          'source_service' => SOURCE_SERVICE,
          'environment' => (defined?(Rails) ? Rails.env.to_s : 'unknown'),
          'app_version' => app_version,
          'details' => blank_to_nil(scrub_details(details)),
        }.compact
      end

      def to_json_line(payload)
        JSON.generate(payload)
      end

      def scrub_details(details)
        text = Foreman::SecurityEvent.sanitize(details)
        return text if text.blank?

        # Redact key=value and JSON-ish "key":"value" for sensitive keys.
        SENSITIVE_SUBSTRINGS.each do |key|
          text = text.gsub(/#{Regexp.escape(key)}\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/i, "#{key}=[REDACTED]")
        end
        # Strip obvious JWT/PAT shaped blobs
        text = text.gsub(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/, '[REDACTED_JWT]')
        text
      end

      def blank_to_nil(value)
        value.presence
      end

      def app_version
        if defined?(Foreman::Version)
          Foreman::Version.new.version
        else
          'unknown'
        end
      rescue StandardError
        'unknown'
      end
    end
  end
end
