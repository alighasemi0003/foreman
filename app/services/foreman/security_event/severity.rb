# frozen_string_literal: true

module Foreman
  module SecurityEvent
    # F-030: six security-logging severity categories.
    #
    # The audit (req 66) required six levels and noted missing Notice/Alert
    # semantics. It did not publish an organizationally named list — this module
    # defines an explicit Syslog-aligned set (excluding EMERGENCY/DEBUG) used by
    # SecurityEvent + the F-041 collector. F-031 owns richer classification/
    # taxonomy policy; severity here is not data-sensitivity classification.
    #
    # status (SUCCESS/DENIED/…) remains orthogonal to severity.
    module Severity
      # Canonical names (uppercase) in decreasing urgency.
      LEVELS = %w[
        ALERT
        CRITICAL
        ERROR
        WARNING
        NOTICE
        INFORMATIONAL
      ].freeze

      SYSLOG = {
        'ALERT' => 1,
        'CRITICAL' => 2,
        'ERROR' => 3,
        'WARNING' => 4,
        'NOTICE' => 5,
        'INFORMATIONAL' => 6,
      }.freeze

      # Map to Ruby/Logging levels actually present (no notice/alert methods).
      RAILS_LEVEL = {
        'ALERT' => :fatal,
        'CRITICAL' => :error,
        'ERROR' => :error,
        'WARNING' => :warn,
        'NOTICE' => :info,
        'INFORMATIONAL' => :info,
      }.freeze

      FROM_RAILS = {
        'fatal' => 'ALERT',
        'error' => 'ERROR',
        'warn' => 'WARNING',
        'warning' => 'WARNING',
        'info' => 'INFORMATIONAL',
        'debug' => 'INFORMATIONAL',
        'unknown' => 'WARNING',
      }.freeze

      # Legacy inline defaults kept as fallback if Taxonomy is unavailable.
      # F-031 Taxonomy is the source of truth when loaded.
      EVENT_DEFAULTS = {
        'ACCOUNT_LOCKOUT' => 'WARNING',
        'CSRF_REJECTED' => 'WARNING',
        'AUTHORIZATION_DENIED' => 'WARNING',
        'SECURITY_CONTROL_REJECTED' => 'WARNING',
        'HTTP_RATE_LIMIT_EXCEEDED' => 'WARNING',
        'HTTP_RATE_LIMIT_FAIL_OPEN' => 'WARNING',
        'HTTP_BODY_TOO_LARGE' => 'WARNING',
        'REAUTH_SUCCESS' => 'NOTICE',
        'REAUTH_FAILED' => 'WARNING',
        'REAUTH_REQUIRED' => 'INFORMATIONAL',
        'REAUTH_UNSUPPORTED' => 'INFORMATIONAL',
        'SESSION_TERMINATE' => 'NOTICE',
        'SESSION_TERMINATE_ALL' => 'NOTICE',
        'JWT_INVALIDATE' => 'NOTICE',
        'JWT_INVALIDATED' => 'NOTICE',
        'REGISTRATION_TOKEN_INVALIDATED' => 'NOTICE',
        'SENSITIVE_EXPORT' => 'NOTICE',
        'HOST_INFO_EXPORT' => 'NOTICE',
        'DIGITAL_SIGNATURE_CREATED' => 'NOTICE',
        'DIGITAL_SIGNATURE_FAILED' => 'WARNING',
        'SETTING_SECURITY_CHANGE' => 'NOTICE',
      }.freeze

      FALLBACK = 'INFORMATIONAL'

      module_function

      def all
        LEVELS.dup
      end

      def known?(name)
        LEVELS.include?(normalize(name).to_s)
      end

      # Returns canonical uppercase name, or nil if blank/unknown.
      def normalize(value)
        return nil if value.nil?

        key = value.to_s.strip.upcase
        return nil if key.empty?
        # Common aliases
        key = 'INFORMATIONAL' if key == 'INFO'
        key = 'WARNING' if key == 'WARN'
        key = 'CRITICAL' if %w[CRIT FATAL EMERGENCY EMERG].include?(key)
        return key if LEVELS.include?(key)

        nil
      end

      # Unknown → FALLBACK (never raises; never drops the event).
      def coerce(value, fallback: FALLBACK)
        normalize(value) || fallback
      end

      def from_rails_level(level)
        return nil if level.nil?

        FROM_RAILS[level.to_s.downcase]
      end

      def to_rails_level(severity)
        RAILS_LEVEL[coerce(severity)] || :info
      end

      def to_syslog(severity)
        SYSLOG[coerce(severity)]
      end

      def default_for_event(event_id)
        begin
          require_relative 'taxonomy' unless defined?(Foreman::SecurityEvent::Taxonomy)
          sev = Taxonomy.default_severity_for(event_id)
          return sev if normalize(sev)
        rescue LoadError, NameError
          # Fall through to inline defaults
        end
        EVENT_DEFAULTS[event_id.to_s] || FALLBACK
      end

      # Resolve severity for a SecurityEvent.log call.
      # Explicit severity wins; else map from Rails level; else event default.
      def resolve(event:, severity: nil, level: nil)
        if (explicit = normalize(severity))
          return explicit
        end
        if level && (from_level = from_rails_level(level))
          # When callers only pass level: :warn (legacy), keep WARNING rather than
          # overriding with a quieter event default.
          return from_level
        end

        default_for_event(event)
      end

      def metadata(severity)
        name = coerce(severity)
        {
          severity: name,
          severity_syslog: to_syslog(name),
          severity_rails: to_rails_level(name).to_s,
        }
      end
    end
  end
end
