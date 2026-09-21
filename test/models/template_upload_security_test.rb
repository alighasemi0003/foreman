# frozen_string_literal: true

require 'test_helper'

class TemplateUploadSecurityTest < ActiveSupport::TestCase
  test 'accepts template within size limit' do
    template = FactoryBot.build(:provisioning_template, :template => "<%#\nname: tiny\n-%>\necho ok\n")
    assert template.valid?, template.errors.full_messages.to_sentence
  end

  test 'rejects template over size limit' do
    oversized = 'x' * (Foreman::UploadSecurity::MAX_TEMPLATE_BYTES + 1)
    template = FactoryBot.build(:provisioning_template, :template => oversized, :name => 'too-big')
    refute template.valid?
    assert template.errors[:template].any? { |m| m.include?('too large') }
  end

  test 'accepts template at exact maximum boundary' do
    body = 'x' * Foreman::UploadSecurity::MAX_TEMPLATE_BYTES
    template = FactoryBot.build(:provisioning_template, :template => body, :name => 'at-limit')
    assert_equal Foreman::UploadSecurity::MAX_TEMPLATE_BYTES, template.template.bytesize
    assert template.valid?, template.errors.full_messages.to_sentence
  end

  test 'ptable and report template inherit size limit' do
    oversized = 'x' * (Foreman::UploadSecurity::MAX_TEMPLATE_BYTES + 1)
    ptable = FactoryBot.build(:ptable, :template => oversized, :name => 'ptable-too-big')
    refute ptable.valid?
    assert ptable.errors[:template].any? { |m| m.include?('too large') }

    report = FactoryBot.build(:report_template, :template => oversized, :name => 'report-too-big')
    refute report.valid?
    assert report.errors[:template].any? { |m| m.include?('too large') }
  end

  test 'filename sanitizes path and control characters' do
    template = FactoryBot.build_stubbed(:provisioning_template, :name => '../evil"name')
    name = template.filename
    refute_includes name, '..'
    refute_includes name, '/'
    refute_includes name, '"'
    assert name.end_with?('.erb')
  end

  test 'handle_template_upload bounds UploadedFile read' do
    controller = TemplatesController.new
    max = Foreman::UploadSecurity::MAX_TEMPLATE_BYTES
    tempfile = Tempfile.new('template')
    tempfile.binmode
    tempfile.write('y' * (max + 50))
    tempfile.rewind
    uploaded = ActionDispatch::Http::UploadedFile.new(
      :filename => 't.erb',
      :type => 'text/plain',
      :tempfile => tempfile
    )
    controller.stubs(:type_name_singular).returns('provisioning_template')
    controller.stubs(:params).returns(
      ActionController::Parameters.new(
        'provisioning_template' => { 'template' => uploaded }
      )
    )
    controller.send(:handle_template_upload)
    content = controller.params['provisioning_template']['template']
    assert_kind_of String, content
    assert_equal max + 1, content.bytesize
  ensure
    tempfile.close!
  end
end
