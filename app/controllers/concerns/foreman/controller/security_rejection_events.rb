# frozen_string_literal: true

module Foreman
  module Controller
    # F-044 — structured SecurityEvent emission for CSRF / authorization rejections.
    # Logging never grants access and never changes the rejection outcome.
    module SecurityRejectionEvents
      extend ActiveSupport::Concern

      private

      def emit_csrf_rejected_event!(reason_code: 'invalid_authenticity_token')
        emit_security_rejection_event!(
          event: 'CSRF_REJECTED',
          status: 'DENIED',
          reason_code: reason_code,
          http_status: 422,
          control: 'csrf'
        )
      end

      def emit_authorization_denied_event!(reason_code: 'permission_denied', http_status: 403, details: nil)
        emit_security_rejection_event!(
          event: 'AUTHORIZATION_DENIED',
          status: 'DENIED',
          reason_code: reason_code,
          http_status: http_status,
          control: 'authorize',
          details: details
        )
      end

      def emit_security_control_rejected_event!(reason_code:, http_status:, control:, details: nil)
        emit_security_rejection_event!(
          event: 'SECURITY_CONTROL_REJECTED',
          status: 'DENIED',
          reason_code: reason_code,
          http_status: http_status,
          control: control,
          details: details
        )
      end

      # Single emission per request; failures never alter the rejection path.
      def emit_security_rejection_event!(event:, status:, reason_code:, http_status:, control:, details: nil)
        return if @_foreman_security_rejection_emitted

        @_foreman_security_rejection_emitted = true

        actor = User.current if User.current&.logged?
        path = request&.path.to_s
        method = request&.request_method.to_s.upcase
        ctrl = respond_to?(:controller_name, true) ? controller_name : nil
        action = respond_to?(:action_name, true) ? action_name : nil

        detail_parts = [
          "control=#{control}",
          "http_status=#{http_status}",
          ("method=#{method}" if method.present?),
          ("controller=#{ctrl}" if ctrl.present?),
          ("action=#{action}" if action.present?),
          ("path=#{path}" if path.present?),
          details.presence,
        ].compact

        Foreman::SecurityEvent.log(
          event: event,
          status: status,
          level: :warn,
          actor: actor&.login,
          actor_id: actor&.id,
          target: [ctrl, action].compact.join('#').presence,
          operation: "#{control}.reject",
          reason_code: reason_code,
          ip: (request.remote_ip if request),
          details: detail_parts.join(' ')
        )
      rescue StandardError => e
        Rails.logger.warn("security rejection event failed: #{e.class}") if defined?(Rails)
        nil
      end
    end
  end
end
