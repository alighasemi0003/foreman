# frozen_string_literal: true

module Foreman
  # Central security-event logging: Actor, IP, timestamp (via logger), Action, Status.
  # Request ID comes from Logging MDC when present.
  #
  # Complementary to Foreman 5.0 Audit.manual_event! login/logout/failed_login entries.
  # Prefer SecurityEvent for reauthentication lifecycle (REAUTH_*) rather than duplicating
  # upstream interactive login Audits.
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
    # @param level [Symbol] :info or :warn
    # @param actor [String, nil] username/login
    # @param ip [String, nil]
    # @param target [String, nil] resource description
    # @param details [String, nil] extra free-text (sanitized)
    def log(event:, status:, level: :info, actor: nil, ip: nil, target: nil, details: nil)
      actor_s = sanitize(actor)
      ip_s = sanitize(ip.presence || current_ip)
      target_s = sanitize(target)
      details_s = sanitize(details)
      request_id = current_request_id

      fields = {
        security_event: event.to_s,
        security_status: status.to_s,
        security_actor: actor_s.presence,
        security_ip: ip_s.presence,
        security_target: target_s.presence,
        security_request_id: request_id,
      }.compact

      message = "SecurityEvent #{event} status=#{status}"
      message += " actor=#{actor_s}" if actor_s.present?
      message += " ip=#{ip_s}" if ip_s.present?
      message += " target=#{target_s}" if target_s.present?
      message += " request_id=#{request_id}" if request_id.present?
      message += " #{details_s}" if details_s.present?

      Foreman::Logging.with_fields(fields) do
        Rails.logger.public_send(level, message)
      end
    end
  end
end
