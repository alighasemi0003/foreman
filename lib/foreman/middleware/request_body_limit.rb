# frozen_string_literal: true

require_relative '../http_body_too_large'

module Foreman
  module Middleware
    # F-028: reject oversized HTTP request bodies before full application parsing.
    #
    # 1. If Content-Length is present and over the path limit → immediate 413.
    # 2. Otherwise wrap rack.input so streamed/chunked reads abort at the limit
    #    without buffering the entire body in this middleware.
    class RequestBodyLimit
      BODY_METHODS = %w[POST PUT PATCH DELETE].freeze

      # Counts bytes as the app reads them; does not preload the body.
      class LimitedInput
        def initialize(input, limit)
          @input = input
          @limit = limit.to_i
          @read = 0
        end

        def read(*args)
          data = @input.read(*args)
          track(data)
          data
        end

        def gets(*args)
          data = @input.gets(*args)
          track(data)
          data
        end

        def each
          return enum_for(:each) unless block_given?

          @input.each do |chunk|
            track(chunk)
            yield chunk
          end
        end

        def rewind
          @read = 0
          @input.rewind if @input.respond_to?(:rewind)
        end

        def close
          @input.close if @input.respond_to?(:close)
        end

        def size
          @input.size if @input.respond_to?(:size)
        end

        def respond_to_missing?(method_name, include_private = false)
          @input.respond_to?(method_name, include_private) || super
        end

        def method_missing(method_name, *args, &block)
          @input.public_send(method_name, *args, &block)
        end

        private

        def track(data)
          return if data.nil?

          @read += data.bytesize
          raise Foreman::HttpBodyTooLarge.new(@limit) if @read > @limit
        end
      end

      def initialize(app)
        @app = app
      end

      def call(env)
        method = env['REQUEST_METHOD'].to_s.upcase
        return @app.call(env) unless BODY_METHODS.include?(method)

        path = env['PATH_INFO'].to_s
        limit = Foreman::UploadSecurity.request_body_limit_for(path)
        return @app.call(env) if limit <= 0

        content_length = env['CONTENT_LENGTH']
        if content_length.present? && content_length.to_i > limit
          return too_large_response(limit, path)
        end

        input = env['rack.input']
        return @app.call(env) if input.nil?

        env['rack.input'] = LimitedInput.new(input, limit)
        env['foreman.request_body_limit'] = limit
        begin
          @app.call(env)
        rescue Foreman::HttpBodyTooLarge => e
          too_large_response(e.limit || limit, path)
        end
      end

      private

      def too_large_response(limit, path)
        begin
          Foreman::SecurityEvent.log(
            event: 'HTTP_BODY_TOO_LARGE',
            status: 'DENIED',
            level: :warn,
            target: path.to_s.truncate(120),
            details: "limit=#{limit}"
          )
        rescue StandardError
          # Logging must not block rejection.
        end

        message = 'Request body is too large.'
        body = { error: { message: message } }.to_json
        [
          413,
          {
            'Content-Type' => 'application/json; charset=utf-8',
            'Content-Length' => body.bytesize.to_s,
            'Cache-Control' => 'no-store',
          },
          [body],
        ]
      end
    end
  end
end
