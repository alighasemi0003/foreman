# frozen_string_literal: true

module Foreman
  module Middleware
    # F-038: refuse public HTTP access to JavaScript/CSS source maps.
    #
    # Defense in depth when ActionDispatch::Static (or a mispackaged image)
    # would otherwise serve *.map from the web root. Development webpack
    # still emits in-memory / eval maps that are not served as static files.
    class BlockSourceMaps
      MAP_PATH = %r{\A(?:/webpack/|/assets/).+\.map(?:\.gz)?\z}i.freeze

      def initialize(app)
        @app = app
      end

      def call(env)
        path = env['PATH_INFO'].to_s
        if MAP_PATH.match?(path)
          return [
            404,
            {
              'Content-Type' => 'text/plain; charset=utf-8',
              'Content-Length' => '10',
              'Cache-Control' => 'no-store',
              'X-Foreman-SourceMap' => 'blocked',
            },
            ["Not Found\n"],
          ]
        end

        @app.call(env)
      end
    end
  end
end
