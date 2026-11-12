# frozen_string_literal: true

module Foreman
  module SecurityEvent
    # F-031: security-event taxonomy and classification-aware logging policy.
    #
    # Separates three concepts:
    #   - severity (urgency) — F-030
    #   - data_classification (sensitivity of metadata) — aligned with F-013 labels
    #   - status/outcome — SUCCESS / FAILURE / DENIED / LOCKED / …
    #
    # Proposed technical policy only — not an organizationally approved standard.
    # Secrets (passwords, tokens, keys, session cookies) are prohibited at every
    # classification; classification never authorizes logging secrets.
    module Taxonomy
      POLICY_ID = 'foreman-security-taxonomy-proposed-v1'

      CATEGORIES = %w[
        authentication
        authorization
        account_password
        session
        data_access
        security_config
        crypto_secret
        security_control_rejection
        availability
        audit_integrity
        unknown
      ].freeze

      # Same labels as Foreman::OutputClassification (F-013); reused for log metadata.
      CLASSIFICATIONS = %w[public internal confidential restricted].freeze

      # Fields that must never appear in details/payload values at any classification.
      PROHIBITED_ALWAYS = %w[
        password passwd passphrase secret token jwt pat bearer
        authorization cookie session_id sessionid private_key
        encryption_key api_key captcha
      ].freeze

      # Metadata generally appropriate for collector search (after sanitize).
      ALLOWED_METADATA = %w[
        ts event_type event_id status severity severity_syslog severity_rails
        event_category data_classification taxonomy_policy retention_days
        actor actor_id target client_ip request_id operation reason_code
        source_service environment app_version details
      ].freeze

      # event_id => policy. severity values must be F-030 canonical names.
      # classification: sensitivity of typical metadata (actor/IP/target), not incident urgency.
      EVENTS = {
        'ACCOUNT_LOCKOUT' => {
          category: 'account_password',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status target reason_code],
          notes: 'F-043 lockout transition; no password material',
        },
        'CAPTCHA_FAILED' => {
          category: 'authentication',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 90,
          required: %w[event_id status],
          notes: 'No captcha answers',
        },
        'PASSWORD_CHANGE_REQUIRED' => {
          category: 'account_password',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'FORCED_PASSWORD_CHANGE_COMPLETED' => {
          category: 'account_password',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'REAUTH_SUCCESS' => {
          category: 'authentication',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'REAUTH_FAILED' => {
          category: 'authentication',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status],
        },
        'REAUTH_REQUIRED' => {
          category: 'authentication',
          severity: 'INFORMATIONAL',
          classification: 'internal',
          retention_days: 90,
          required: %w[event_id status],
        },
        'REAUTH_UNSUPPORTED' => {
          category: 'authentication',
          severity: 'INFORMATIONAL',
          classification: 'internal',
          retention_days: 90,
          required: %w[event_id status],
        },
        'CSRF_REJECTED' => {
          category: 'security_control_rejection',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 180,
          required: %w[event_id status],
          notes: 'F-044',
        },
        'AUTHORIZATION_DENIED' => {
          category: 'authorization',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 180,
          required: %w[event_id status],
          notes: 'F-044',
        },
        'SECURITY_CONTROL_REJECTED' => {
          category: 'security_control_rejection',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 180,
          required: %w[event_id status],
          notes: 'F-044 / unsafe HTTP method etc.',
        },
        'HTTP_RATE_LIMIT_EXCEEDED' => {
          category: 'availability',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 90,
          required: %w[event_id status],
        },
        'HTTP_RATE_LIMIT_FAIL_OPEN' => {
          category: 'availability',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 180,
          required: %w[event_id status],
        },
        'HTTP_BODY_TOO_LARGE' => {
          category: 'security_control_rejection',
          severity: 'WARNING',
          classification: 'internal',
          retention_days: 90,
          required: %w[event_id status],
        },
        'SESSION_TERMINATE' => {
          category: 'session',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
          notes: 'Never log session cookie/id values',
        },
        'SESSION_TERMINATE_ALL' => {
          category: 'session',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'JWT_INVALIDATE' => {
          category: 'crypto_secret',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status actor],
          notes: 'Token values prohibited; metadata only',
        },
        'JWT_INVALIDATE_ALL' => {
          category: 'crypto_secret',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'JWT_INVALIDATE_SEARCH' => {
          category: 'crypto_secret',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'REGISTRATION_TOKEN_INVALIDATED' => {
          category: 'crypto_secret',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status],
        },
        'HOST_INFO_EXPORT' => {
          category: 'data_access',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'HOST_INHERITED_PARAMETERS_EXPORT' => {
          category: 'data_access',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'SENSITIVE_EXPORT' => {
          category: 'data_access',
          severity: 'NOTICE',
          classification: 'confidential',
          retention_days: 365,
          required: %w[event_id status],
        },
        'SETTING_SECURITY_CHANGE' => {
          category: 'security_config',
          severity: 'NOTICE',
          classification: 'internal',
          retention_days: 365,
          required: %w[event_id status actor],
        },
        'COLLECTOR_INTEGRITY_FAILURE' => {
          category: 'audit_integrity',
          severity: 'CRITICAL',
          classification: 'internal',
          retention_days: 730,
          required: %w[event_id status],
          notes: 'Little PII; high urgency — severity ≠ classification',
        },
      }.freeze

      UNKNOWN_DEFAULT = {
        category: 'unknown',
        severity: 'INFORMATIONAL',
        classification: 'internal',
        retention_days: 90,
        required: %w[event_id status],
        notes: 'Safe fallback — event still emitted; never dropped',
      }.freeze

      # Handling hints by data classification (proposed).
      CLASSIFICATION_HANDLING = {
        'public' => {
          destinations: %w[rails_log collector],
          redaction: 'standard',
          transport: 'lab_tcp_or_org_siem',
        },
        'internal' => {
          destinations: %w[rails_log collector],
          redaction: 'standard',
          transport: 'lab_tcp_or_org_siem',
        },
        'confidential' => {
          destinations: %w[rails_log collector],
          redaction: 'standard_plus_no_body_content',
          transport: 'collector_preferred_protected_store',
        },
        'restricted' => {
          destinations: %w[collector],
          redaction: 'metadata_only_no_secret_material',
          transport: 'protected_store_only',
          notes: 'Still never logs raw secrets; prefer collector over verbose local dumps',
        },
      }.freeze

      module_function

      def policy_id
        POLICY_ID
      end

      def categories
        CATEGORIES.dup
      end

      def classifications
        CLASSIFICATIONS.dup
      end

      def known_event?(event_id)
        EVENTS.key?(event_id.to_s)
      end

      def normalize_classification(value)
        key = value.to_s.downcase.strip
        return key if CLASSIFICATIONS.include?(key)

        # Align with F-013 when available
        if defined?(Foreman::OutputClassification)
          return Foreman::OutputClassification.normalize(key)
        end

        'internal'
      end

      def normalize_category(value)
        key = value.to_s.downcase.strip
        CATEGORIES.include?(key) ? key : 'unknown'
      end

      # Full policy hash for an event_id (always returns a Hash; never nil).
      def lookup(event_id)
        base = EVENTS[event_id.to_s] || UNKNOWN_DEFAULT
        {
          event_id: event_id.to_s,
          category: base[:category],
          severity: base[:severity],
          classification: base[:classification],
          retention_days: base[:retention_days],
          required: Array(base[:required]),
          notes: base[:notes],
          known: EVENTS.key?(event_id.to_s),
          taxonomy_policy: POLICY_ID,
          prohibited_fields: PROHIBITED_ALWAYS,
          handling: CLASSIFICATION_HANDLING[base[:classification]] || CLASSIFICATION_HANDLING['internal'],
        }
      end

      # Resolve classification for a log call (explicit override allowed).
      def resolve_classification(event:, classification: nil)
        if classification
          return normalize_classification(classification)
        end

        lookup(event)[:classification]
      end

      def resolve_category(event:, category: nil)
        return normalize_category(category) if category

        lookup(event)[:category]
      end

      def default_severity_for(event_id)
        lookup(event_id)[:severity]
      end

      def handling_for(classification)
        CLASSIFICATION_HANDLING[normalize_classification(classification)] ||
          CLASSIFICATION_HANDLING['internal']
      end

      def catalog
        EVENTS.keys.sort.map { |id| lookup(id) }
      end
    end
  end
end
