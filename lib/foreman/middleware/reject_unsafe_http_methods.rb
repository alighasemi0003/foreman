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
          log_security_control_rejection(env, method)
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

      private

      # F-044: structured event for rejected non-REST / WebDAV-style verbs.
      def log_security_control_rejection(env, method)
        ip = env['action_dispatch.remote_ip']&.to_s.presence ||
             env['HTTP_X_FORWARDED_FOR']&.to_s&.split(',')&.first&.strip.presence ||
             env['REMOTE_ADDR']
        path = env['PATH_INFO'].to_s
        Foreman::SecurityEvent.log(
          event: 'SECURITY_CONTROL_REJECTED',
          status: 'DENIED',
          level: :warn,
          actor: nil,
          reason_code: 'unsafe_http_method',
          operation: 'http_method.reject',
          ip: ip,
          details: "control=http_method http_status=405 method=#{method} path=#{path}"
        )
      rescue StandardError
        nil
      end
    end
  end
end
