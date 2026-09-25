# frozen_string_literal: true

module Foreman
  module Controller
    # Interactive local users with password_change_required must change password
    # before using the rest of the UI (and session-backed API/UI-chrome calls).
    # Machine/token API auth (api_authenticated_session) is unaffected.
    #
    # Hooked from ApplicationController and Api::BaseController after authorize.
    module PasswordChangeRequired
      extend ActiveSupport::Concern

      private

      def enforce_password_change_required
        # remote_user_provided? lives on ApplicationController; API controllers may lack it.
        return if respond_to?(:remote_user_provided?, true) && remote_user_provided?

        # Prefer the browser session user. In tests, API controllers can leave
        # User.current as a fixture admin via the api_request? auth short-circuit.
        user = password_change_required_session_user
        return unless user&.password_change_required?

        # Token/basic API sets api_authenticated_session; browser sessions do not.
        return unless Foreman::Reauthentication.interactive_session?(session)
        return if password_change_required_request_allowed?

        if password_change_required_api_style_request?
          # Never redirect JSON/API chrome to the HTML password page (blank pages).
          # /notification_recipients must not be an auth redirect target or bypass.
          head :forbidden
          return
        end

        warning(_("You must change your password before continuing.")) if respond_to?(:warning, true)
        redirect_to main_app.edit_user_path(user)
      end

      def password_change_required_session_user
        if session[:user].present?
          User.unscoped.find_by(id: session[:user]) || User.current
        else
          User.current
        end
      end

      def password_change_required_request_allowed?
        # Dedicated minimal password-change page + logout only.
        controller_path == 'users' && %w[edit update logout].include?(action_name)
      end

      def password_change_required_api_style_request?
        return true if api_request?
        return true if controller_path == 'notification_recipients'
        return true if controller_path.to_s.start_with?('api/')

        false
      end
    end
  end
end
