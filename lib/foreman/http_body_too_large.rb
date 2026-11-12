# frozen_string_literal: true

module Foreman
  # Raised when a request body exceeds the configured byte limit while being read.
  # Mapped to HTTP 413 via action_dispatch.rescue_responses.
  class HttpBodyTooLarge < StandardError
    attr_reader :limit

    def initialize(limit = nil)
      @limit = limit
      super(limit ? "Request body exceeds limit of #{limit} bytes" : 'Request body is too large')
    end
  end
end
