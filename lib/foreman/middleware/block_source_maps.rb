# frozen_string_literal: true

module Foreman
  module Middleware
    # F-038 / F-039: refuse public HTTP access to debug artifacts and application
    # source-like paths that must never be served as static content.
    #
    # Rails only serves from public/ by default; this is defense in depth if a
    # misconfigured proxy or accidental copy places source under the web root.
    # It does not hide Ruby from filesystem readers inside the container.
    class BlockSourceMaps
      MAP_PATH = %r{\A(?:/webpack/|/assets/).+\.map(?:\.gz)?\z}i.freeze

      # Source-tree prefixes that are never legitimate public URLs.
      # Do NOT include /webpack or /assets — those are intentional static roots.
      SOURCE_PREFIX = %r{\A/(?:app|config|lib|db|test|spec|script|bin|bundler\.d|vendor)/}i.freeze

      # File extensions that should not be fetchable as static assets.
      SOURCE_EXT = %r{\.(?:rb|erb|rake|builder|jbuilder|rjs|rhtml|yml|yaml)(?:\.gz)?\z}i.freeze

      def initialize(app)
        @app = app
      end

      def call(env)
        path = env['PATH_INFO'].to_s
        if blocked?(path)
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

      private

      def blocked?(path)
        return true if MAP_PATH.match?(path)
        return true if SOURCE_PREFIX.match?(path)
        return true if SOURCE_EXT.match?(path) && static_asset_path?(path)

        false
      end

      def static_asset_path?(path)
        path.start_with?('/webpack/', '/assets/', '/javascripts/', '/stylesheets/')
      end
    end
  end
end
