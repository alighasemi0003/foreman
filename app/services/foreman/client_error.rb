# frozen_string_literal: true

module Foreman
  # Client-safe error messaging for unexpected exceptions.
  module ClientError
    INTERNAL_ERROR_MESSAGE = N_(
      "Internal Server Error: the server was unable to finish the request. " \
      "This may be caused by unavailability of some required service, incorrect API call or a server-side bug. " \
      "There may be more information in the server's logs."
    )

    module_function

    def internal_server_error_message
      _(INTERNAL_ERROR_MESSAGE)
    end

    # Foreman::Exception and ProxyAPI::ProxyException carry intentional user-facing messages.
    def client_message(exception)
      if exception.is_a?(::Foreman::Exception) ||
         (defined?(::ProxyAPI::ProxyException) && exception.is_a?(::ProxyAPI::ProxyException))
        exception.message
      else
        internal_server_error_message
      end
    end
  end
end
