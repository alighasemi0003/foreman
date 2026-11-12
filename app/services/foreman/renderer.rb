module Foreman
  module Renderer
    PREVIEW_MODE = 'preview'
    REAL_MODE = 'real'
    AVAILABLE_RENDERING_MODES = [PREVIEW_MODE, REAL_MODE]

    class << self
      attr_writer :config

      def config
        @config ||= Foreman::Renderer::Configuration.new
      end

      def configure
        yield config
      end

      # Returns an open Tempfile under Rails.root/tmp. Caller must close!/unlink
      # after use (see Orchestration::SshProvision). Avoid Tempfile.open(&block)
      # here: the block form closes but leaves the path until GC finalizer (F-020).
      def render_template_to_tempfile(template:, prefix:, host: nil, params: {}, variables: {}, options: {})
        source = get_source(template: template, host: host)
        scope = get_scope(host: host, params: params, variables: variables)
        file = Tempfile.new(prefix, Rails.root.join('tmp'))
        begin
          file.print render(source, scope)
          file.flush
          file.chmod options[:mode] if options[:mode]
          file
        rescue StandardError
          file.close!
          raise
        end
      end

      def get_source(template:, klass: nil, **args)
        klass ||= Foreman::Renderer::Source::Database
        klass.new(template)
      end

      def get_scope(source: nil, klass: nil, host: nil, params: {}, variables: {}, mode: REAL_MODE, template: nil, template_input_values: {})
        source ||= get_source(template: template)
        klass ||= template&.default_render_scope_class || Foreman::Renderer::Scope::Provisioning
        klass.new(source: source, host: host, params: params, variables: variables, mode: mode, template_input_values: template_input_values)
      end

      def renderer
        Setting[:safemode_render] ? Foreman::Renderer::SafeModeRenderer : Foreman::Renderer::UnsafeModeRenderer
      end

      delegate :render, to: :renderer
    end
  end
end
