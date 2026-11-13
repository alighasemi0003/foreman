# frozen_string_literal: true

require 'test_helper'
require 'fileutils'
require 'foreman/public_source_exposure'

class Foreman::PublicSourceExposureTest < ActiveSupport::TestCase
  setup do
    @root = Dir.mktmpdir('foreman-f039-public')
  end

  teardown do
    FileUtils.rm_rf(@root) if @root && File.directory?(@root)
  end

  test 'scan passes for clean public root' do
    FileUtils.mkdir_p(File.join(@root, 'webpack'))
    File.write(File.join(@root, 'webpack', 'bundle.js'), 'console.log(1)')
    result = Foreman::PublicSourceExposure.scan(root: @root)
    assert result[:ok]
    assert_empty result[:findings]
  end

  test 'scan fails when ruby or map present under public' do
    FileUtils.mkdir_p(File.join(@root, 'webpack'))
    File.write(File.join(@root, 'webpack', 'x.js.map'), '{}')
    File.write(File.join(@root, 'leak.rb'), 'puts 1')
    result = Foreman::PublicSourceExposure.scan(root: @root)
    refute result[:ok]
    assert result[:findings].any? { |f| f.end_with?('.map') || f.end_with?('.rb') }
  end

  test 'report includes task metadata' do
    report = Foreman::PublicSourceExposure.report
    assert_equal 'F-039', report[:task]
    assert report.key?(:ok)
  end
end
