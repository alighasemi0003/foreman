# frozen_string_literal: true

module Foreman
  module Middleware
    # Reject HTTP methods that Foreman never uses and that are commonly abused
    # (TRACE/TRACK echo, CONNECT tunneling, WebDAV). Legitimate REST verbs
    # (GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS) pass through to Rails routing.
    class RejectUnsafeHttpMethods
      ALLOWED = %w[GET HEAD POST PUT PATCH DELETE OPTIONS].freeze
      UNSAFE = %w[
        TRACE TRACK CONNECT
        PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK
      ].freeze

      def initialize(app)
        @app = app
      end

      def call(env)
        method = env['REQUEST_METHOD'].to_s.upcase
        if UNSAFE.include?(method) || !ALLOWED.include?(method)
          return [
            405,
            {
              'Content-Type' => 'text/plain; charset=utf-8',
              'Allow' => ALLOWED.join(', '),
              'Content-Length' => '18',
            },
            ["Method Not Allowed\n"],
          ]
        end
        @app.call(env)
      end
    end
  end
end
