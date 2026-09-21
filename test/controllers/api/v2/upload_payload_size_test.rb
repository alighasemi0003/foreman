# frozen_string_literal: true

require 'test_helper'

class Api::V2::UploadPayloadSizeTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    User.current = users(:admin)
  end

  test 'facts rejects when request body exceeds limit' do
    Foreman::UploadSecurity.stubs(:request_body_too_large?).returns(true)
    post :facts, params: { :name => 'host.example.com', :facts => { 'domain' => 'example.com' } },
      session: set_session_user
    assert_response :payload_too_large
  end

  test 'facts proceeds when body is within limit' do
    Foreman::UploadSecurity.stubs(:request_body_too_large?).returns(false)
    Host::Managed.stubs(:import_host).returns(FactoryBot.build_stubbed(:host))
    HostFactImporter.any_instance.stubs(:import_facts).returns(true)
    post :facts, params: { :name => 'host.example.com', :facts => { 'domain' => 'example.com' } },
      session: set_session_user
    assert_response :success
  end
end

class Api::V2::ConfigReportPayloadSizeTest < ActionController::TestCase
  tests Api::V2::ConfigReportsController

  setup do
    User.current = users(:admin)
  end

  test 'create rejects when request body exceeds limit' do
    Foreman::UploadSecurity.stubs(:request_body_too_large?).returns(true)
    post :create, params: {
      :config_report => {
        :host => 'host.example.com',
        :reported_at => Time.now.utc.to_s,
        :status => { :applied => 0 },
        :metrics => {},
      },
    }, session: set_session_user
    assert_response :payload_too_large
  end

  test 'create proceeds when body is within limit' do
    Foreman::UploadSecurity.stubs(:request_body_too_large?).returns(false)
    report = FactoryBot.build_stubbed(:config_report)
    report.stubs(:errors).returns(ActiveModel::Errors.new(report))
    ConfigReport.stubs(:import).returns(report)
    post :create, params: {
      :config_report => {
        :host => 'host.example.com',
        :reported_at => Time.now.utc.to_s,
        :status => { :applied => 0 },
        :metrics => {},
      },
    }, session: set_session_user
    assert_response :success
  end
end
