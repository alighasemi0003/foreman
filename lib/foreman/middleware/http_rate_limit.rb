# frozen_string_literal: true

module Foreman
  module Middleware
    # Enforces Foreman::HttpRateLimit before controllers run.
    # Inserted after ActionDispatch::RemoteIp so client IP is trusted-proxy aware.
    class HttpRateLimit
      def initialize(app)
        @app = app
      end

      def call(env)
        request = ActionDispatch::Request.new(env)
        category = Foreman::HttpRateLimit.classify(request.path, request.request_method)
        return @app.call(env) if category == :exempt || !Foreman::HttpRateLimit.enabled?

        client_ip = request.remote_ip
        result = Foreman::HttpRateLimit.check!(category: category, client_ip: client_ip)
        return @app.call(env) if result.allowed

        log_throttle(request, result, client_ip)
        throttle_response(request, result)
      end

      private

      def log_throttle(request, result, client_ip)
        Foreman::SecurityEvent.log(
          event: 'HTTP_RATE_LIMIT_EXCEEDED',
          status: result.error == :store_unavailable ? 'UNAVAILABLE' : 'DENIED',
          level: :warn,
          ip: client_ip,
          target: request.path.to_s.truncate(120),
          details: "category=#{result.category} count=#{result.count} limit=#{result.limit}"
        )
      end

      def throttle_response(request, result)
        retry_after = result.retry_after.to_i
        headers = {
          'Content-Type' => content_type(request),
          'Retry-After' => retry_after.to_s,
          'Cache-Control' => 'no-store',
          'X-RateLimit-Limit' => result.limit.to_s,
          'X-RateLimit-Remaining' => '0',
        }
        body = body_for(request, result, retry_after)
        headers['Content-Length'] = body.bytesize.to_s
        [429, headers, [body]]
      end

      def content_type(request)
        if api_request?(request) || wants_json?(request)
          'application/json; charset=utf-8'
        else
          'text/plain; charset=utf-8'
        end
      end

      def body_for(request, result, retry_after)
        message = if result.error == :store_unavailable
                    'Service temporarily unavailable. Try again later.'
                  else
                    'Too many requests. Try again later.'
                  end
        if api_request?(request) || wants_json?(request)
          { error: { message: message, retry_after: retry_after } }.to_json
        else
          "#{message}\n"
        end
      end

      def api_request?(request)
        request.path.to_s.start_with?('/api')
      end

      def wants_json?(request)
        accept = request.get_header('HTTP_ACCEPT').to_s
        accept.include?('application/json')
      end
    end
  end
end
