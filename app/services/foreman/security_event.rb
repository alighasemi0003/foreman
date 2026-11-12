# frozen_string_literal: true

require_relative 'security_event/severity'
require_relative 'security_event/taxonomy'
require_relative 'security_event/payload'
require_relative 'security_event/forwarder'

module Foreman
  # Central security-event logging: Actor, IP, timestamp (via logger), Action, Status.
  # Request ID comes from Logging MDC when present.
  #
  # Complementary to Foreman 5.0 Audit.manual_event! login/logout/failed_login entries.
  # Prefer SecurityEvent for reauthentication lifecycle (REAUTH_*) rather than duplicating
  # upstream interactive login Audits.
  #
  # F-041: also builds a structured JSON payload and best-effort forwards it to an
  # external collector when FOREMAN_SECURITY_EVENTS_ENABLED=true.
  #
  # F-030: structured severity (ALERT…INFORMATIONAL) is carried on the payload and
  # mapped onto Rails logger levels — Logger internals are not patched.
  module SecurityEvent
    module_function

    # Strip control characters so user-controlled fields cannot forge extra log lines.
    def sanitize(value)
      value.to_s.gsub(/[\x00-\x1f\x7f]/, ' ').squeeze(' ').strip.truncate(200)
    end

    def current_ip
      ::Logging.mdc['remote_ip'].presence
    end

    def current_request_id
      ::Logging.mdc['request'].presence
    end

    # @param event [String] machine-readable event id, e.g. REAUTH_SUCCESS
    # @param status [String] SUCCESS / FAILURE / DENIED / LOCKED / UNLOCKED / UNSUPPORTED
    # @param level [Symbol, nil] optional Rails logger level (:info/:warn/:error/:fatal).
    #   When omitted, derived from severity. Kept for backward compatibility.
    # @param severity [String, Symbol, nil] F-030 category (ALERT…INFORMATIONAL)
    # @param classification [String, Symbol, nil] F-031 data sensitivity (F-013 labels)
    # @param category [String, Symbol, nil] F-031 event category override
    # @param actor [String, nil] username/login
    # @param actor_id [Integer, nil]
    # @param ip [String, nil]
    # @param target [String, nil] resource description
    # @param details [String, nil] extra free-text (sanitized)
    # @param operation [String, nil]
    # @param reason_code [String, nil]
    def log(event:, status:, level: nil, severity: nil, classification: nil, category: nil,
             actor: nil, actor_id: nil, ip: nil, target: nil, details: nil, operation: nil,
             reason_code: nil)
      actor_s = sanitize(actor)
      ip_s = sanitize(ip.presence || current_ip)
      target_s = sanitize(target)
      # Scrub secrets for both local logs and the central collector payload.
      details_s = Payload.scrub_details(details)
      request_id = current_request_id

      sev = Severity.resolve(event: event, severity: severity, level: level)
      data_class = Taxonomy.resolve_classification(event: event, classification: classification)
      event_category = Taxonomy.resolve_category(event: event, category: category)
      rails_level = level.present? ? level.to_sym : Severity.to_rails_level(sev)
      # Guard unknown Rails levels — fall back safely.
      unless Rails.logger.respond_to?(rails_level)
        rails_level = Severity.to_rails_level(sev)
      end

      fields = {
        security_event: event.to_s,
        security_status: status.to_s,
        security_severity: sev,
        security_category: event_category,
        security_classification: data_class,
        security_actor: actor_s.presence,
        security_ip: ip_s.presence,
        security_target: target_s.presence,
        security_request_id: request_id,
      }.compact

      message = "SecurityEvent #{event} status=#{status} severity=#{sev} " \
                "category=#{event_category} classification=#{data_class}"
      message += " actor=#{actor_s}" if actor_s.present?
      message += " ip=#{ip_s}" if ip_s.present?
      message += " target=#{target_s}" if target_s.present?
      message += " request_id=#{request_id}" if request_id.present?
      message += " #{details_s}" if details_s.present?

      Foreman::Logging.with_fields(fields) do
        Rails.logger.public_send(rails_level, message)
      end

      payload = Payload.build(
        event: event,
        status: status,
        severity: sev,
        level: rails_level,
        classification: data_class,
        category: event_category,
        actor: actor_s,
        actor_id: actor_id,
        target: target_s,
        ip: ip_s,
        details: details_s,
        operation: operation,
        reason_code: reason_code,
        request_id: request_id
      )
      Forwarder.enqueue(payload)
      payload
    rescue StandardError => e
      # Local logging / forwarding must never break the request path.
      begin
        Rails.logger.warn("SecurityEvent.log failed: #{e.class}") if defined?(Rails)
      rescue StandardError
        nil
      end
      nil
    end
  end
end
