# frozen_string_literal: true

require_relative 'severity'
require_relative 'taxonomy'

module Foreman
  module SecurityEvent
    # Builds the centralized security-event JSON schema (F-041).
    # Never include secrets — sanitize and scrub known sensitive tokens.
    #
    # F-030: severity / severity_syslog / severity_rails
    # F-031: event_category / data_classification / taxonomy_policy / retention_days
    # status (SUCCESS/DENIED/…) remains orthogonal to severity and classification.
    module Payload
      SOURCE_SERVICE = 'foreman'
      EVENT_TYPE = 'security'

      SENSITIVE_SUBSTRINGS = Taxonomy::PROHIBITED_ALWAYS

      module_function

      def build(event:, status:, actor: nil, actor_id: nil, target: nil, ip: nil,
                details: nil, operation: nil, reason_code: nil, request_id: nil,
                severity: nil, level: nil, classification: nil, category: nil)
        policy = Taxonomy.lookup(event)
        sev = Severity.resolve(event: event, severity: severity, level: level)
        sev_meta = Severity.metadata(sev)
        data_class = Taxonomy.resolve_classification(event: event, classification: classification)
        event_category = Taxonomy.resolve_category(event: event, category: category)

        {
          'ts' => Time.now.utc.iso8601(3),
          'event_type' => EVENT_TYPE,
          'event_id' => event.to_s,
          'status' => status.to_s,
          'severity' => sev_meta[:severity],
          'severity_syslog' => sev_meta[:severity_syslog],
          'severity_rails' => sev_meta[:severity_rails],
          'event_category' => event_category,
          'data_classification' => data_class,
          'taxonomy_policy' => Taxonomy.policy_id,
          'retention_days' => policy[:retention_days],
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
