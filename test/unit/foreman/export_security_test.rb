# frozen_string_literal: true

require 'test_helper'

class Foreman::ExportSecurityTest < ActiveSupport::TestCase
  setup do
    User.current = users(:admin)
    @host = FactoryBot.create(:host)
    @secret = 'synth-export-secret-f019-001'
    @visible = 'synth-visible-param-f019'
    @host.host_parameters.create!(:name => 'synth_secret', :value => @secret, :hidden_value => true)
    @host.host_parameters.create!(:name => 'synth_visible', :value => @visible, :hidden_value => false)
    @host.clear_host_parameters_cache!
  end

  test 'redact_host_info replaces hidden parameter values only' do
    info = @host.info
    assert_equal @secret, info.dig('parameters', 'synth_secret')
    assert_equal @visible, info.dig('parameters', 'synth_visible')

    redacted = Foreman::ExportSecurity.redact_host_info(info, @host)
    assert_equal HiddenValue::HIDDEN_VALUE, redacted.dig('parameters', 'synth_secret')
    assert_equal @visible, redacted.dig('parameters', 'synth_visible')
    # Original info must remain untouched for operational consumers.
    assert_equal @secret, info.dig('parameters', 'synth_secret')
  end

  test 'serialize_parameters_for_export redacts by default' do
    param = FactoryBot.create(:common_parameter, :name => 'inherited_secret',
      :value => @secret, :hidden_value => true)
    payload = Foreman::ExportSecurity.serialize_parameters_for_export([param], reveal_hidden: false)
    assert_equal 1, payload.size
    assert_equal HiddenValue::HIDDEN_VALUE, payload.first['value']
    refute_includes payload.first.values.map(&:to_s).join, @secret
  end

  test 'serialize_parameters_for_export reveals when authorized' do
    param = FactoryBot.create(:common_parameter, :name => 'inherited_secret2',
      :value => @secret, :hidden_value => true)
    payload = Foreman::ExportSecurity.serialize_parameters_for_export([param], reveal_hidden: true)
    assert_equal @secret, payload.first['value']
  end

  test 'apply_sensitive_download_headers sets no-store' do
    response = ActionDispatch::Response.new
    Foreman::ExportSecurity.apply_sensitive_download_headers(response)
    assert_match(/no-store/, response.headers['Cache-Control'])
    assert_equal 'no-cache', response.headers['Pragma']
  end
end
