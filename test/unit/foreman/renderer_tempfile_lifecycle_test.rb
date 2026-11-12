# frozen_string_literal: true

require 'test_helper'

class Foreman::RendererTempfileLifecycleTest < ActiveSupport::TestCase
  class DummyTemplate
    def template
      'echo hello-f020'
    end

    def name
      'f020-finish'
    end

    def default_render_scope_class
      Foreman::Renderer::Scope::Base
    end
  end

  test 'render_template_to_tempfile returns an open file under tmp that close! removes' do
    template = mock('template')
    template.stubs(:template).returns('echo secret-finish')
    template.stubs(:name).returns('finish')
    template.stubs(:default_render_scope_class).returns(Foreman::Renderer::Scope::Base)
    template.stubs(:id).returns(1)

    source = Foreman::Renderer::Source::String.new(name: 't', content: 'echo secret-finish')
    Foreman::Renderer.stubs(:get_source).returns(source)
    Foreman::Renderer.stubs(:get_scope).returns(Foreman::Renderer::Scope::Base.new(source: source))
    Foreman::Renderer.stubs(:render).returns('echo secret-finish')

    file = Foreman::Renderer.render_template_to_tempfile(template: template, prefix: 'f020host')
    assert File.exist?(file.path)
    assert_includes File.expand_path(file.path), File.expand_path(Rails.root.join('tmp').to_s)
    path = file.path
    file.close!
    refute File.exist?(path), 'close! must unlink provisioning tempfile'
  end
end
