# frozen_string_literal: true

module Foreman
  module Controller
    module Reauthentication
      extend ActiveSupport::Concern

      # Returns false and renders when step-up is required; true when allowed to proceed.
      def ensure_reauthenticated!(action_key)
        return true unless Foreman::Reauthentication.required_for?(action_key, session: session)

        actor = Foreman::Reauthentication.real_actor(session)
        Foreman::SecurityEvent.log(
          event: 'REAUTH_REQUIRED',
          status: 'DENIED',
          level: :warn,
          actor: actor&.login,
          ip: request.remote_ip,
          target: action_key,
          details: impersonation_details
        )
        render_reauthentication_required(action_key)
        false
      end

      # For users#update: gate if any sensitive transition is present.
      def ensure_user_update_reauthenticated!(user, params_hash)
        keys = Foreman::Reauthentication.user_update_action_keys(user, params_hash)
        return true if keys.empty?

        # Single challenge: gate on the first enabled key that still needs reauth.
        keys.each do |key|
          return false unless ensure_reauthenticated!(key)
        end
        true
      end

      def ensure_meta_settings_reauthenticated!(setting_name)
        action_key = Foreman::Reauthentication.action_key_for_setting(setting_name)
        return true if action_key.nil?

        ensure_reauthenticated!(action_key)
      end

      def render_reauthentication_required(action_key)
        actor = Foreman::Reauthentication.real_actor(session)
        payload = {
          error: {
            message: _('Re-authentication required to perform this action.'),
            details: _('Please confirm your identity and retry.'),
            reauthentication_required: true,
            action: action_key,
            reauthentication_supported: Foreman::Reauthentication.supported_for?(actor),
          },
        }

        # Legacy HTML enhanced via JS sends X-Foreman-Accept-Reauth so the modal
        # can open. Non-JS browsers keep flash + redirect fail-closed.
        if structured_reauthentication_response?
          render json: payload, status: :forbidden
          return
        end

        respond_to do |format|
          format.json { render json: payload, status: :forbidden }
          format.html do
            error(_('Re-authentication required to perform this action.'))
            redirect_back(fallback_location: main_app.root_path)
          end
          format.any { render json: payload, status: :forbidden }
        end
      end

      def structured_reauthentication_response?
        return true if request.format.json?
        return true if request.headers['HTTP_X_FOREMAN_ACCEPT_REAUTH'].to_s == '1'

        false
      end

      def impersonation_details
        return nil if session[:impersonated_by].blank?

        "effective_user=#{User.current&.login}"
      end
    end
  end
end
