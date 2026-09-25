# frozen_string_literal: true

module Foreman
  module Controller
    # Interactive local users with password_change_required must change password
    # before using the rest of the UI. Machine/API auth is unaffected.
    #
    # Hooked from ApplicationController after require_login and before authorize.
    module PasswordChangeRequired
      extend ActiveSupport::Concern

      private

      def enforce_password_change_required
        return if api_request?
        return if remote_user_provided?
        return unless User.current&.password_change_required?

        return if password_change_required_request_allowed?

        warning(_("You must change your password before continuing."))
        redirect_to main_app.edit_user_path(User.current)
      end

      def password_change_required_request_allowed?
        return true if controller_path == 'users' && %w[edit update logout].include?(action_name)
        return true if controller_path == 'notification_recipients'
        return true if controller_path.to_s.start_with?('api/')

        false
      end
    end
  end
end
