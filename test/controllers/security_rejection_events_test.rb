# frozen_string_literal: true

require 'test_helper'

class SecurityRejectionEventsCsrfTest < ActionController::TestCase
  tests UsersController

  setup do
    ActionController::Base.allow_forgery_protection = true
    @admin = users(:admin)
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'valid CSRF request does not emit CSRF_REJECTED' do
    Foreman::SecurityEvent.expects(:log).with(has_entries(event: 'CSRF_REJECTED')).never
    token = @controller.send(:form_authenticity_token)
    post :logout, params: { authenticity_token: token }, session: set_session_user
    assert_response :redirect
  end

  test 'invalid CSRF token rejects request and emits CSRF_REJECTED once' do
    calls = []
    Foreman::SecurityEvent.stubs(:log).with do |kwargs|
      calls << kwargs if kwargs[:event].to_s == 'CSRF_REJECTED'
      true
    end

    assert_raises ActionController::InvalidAuthenticityToken do
      post :logout, params: { authenticity_token: 'totally-invalid-token' }, session: set_session_user
    end

    assert_equal 1, calls.size
    ev = calls.first
    assert_equal 'DENIED', ev[:status]
    assert_equal 'invalid_authenticity_token', ev[:reason_code]
    assert_equal @admin.login, ev[:actor]
    refute_match(/totally-invalid-token/, ev[:details].to_s)
    refute_match(/password/i, ev[:details].to_s)
  end

  test 'missing CSRF token emits CSRF_REJECTED without token material' do
    calls = []
    Foreman::SecurityEvent.stubs(:log).with do |kwargs|
      calls << kwargs if kwargs[:event].to_s == 'CSRF_REJECTED'
      true
    end

    assert_raises ActionController::InvalidAuthenticityToken do
      post :logout, session: set_session_user
    end

    assert_equal 1, calls.size
    refute_includes calls.first[:details].to_s, "\n"
  end
end

class SecurityRejectionEventsAuthzTest < ActionController::TestCase
  tests ArchitecturesController

  setup do
    @role = FactoryBot.create(:role, :name => "f044-viewer-#{SecureRandom.hex(4)}")
    @role.add_permissions!(:view_architectures)
    @user = FactoryBot.create(:user, :roles => [@role])
  end

  test 'unauthorized create emits AUTHORIZATION_DENIED and returns forbidden' do
    calls = []
    Foreman::SecurityEvent.stubs(:log).with do |kwargs|
      calls << kwargs if kwargs[:event].to_s == 'AUTHORIZATION_DENIED'
      true
    end

    post :create,
         params: { architecture: { name: "f044-arch-#{SecureRandom.hex(3)}" } },
         session: set_session_user(@user)
    assert_response :forbidden
    assert_equal 1, calls.size
    ev = calls.first
    assert_equal 'DENIED', ev[:status]
    assert_equal 'permission_denied', ev[:reason_code]
    assert_equal @user.login, ev[:actor]
    assert_includes ev[:details].to_s, 'http_status=403'
  end

  test 'allowed index does not emit AUTHORIZATION_DENIED' do
    Foreman::SecurityEvent.expects(:log).with(has_entries(event: 'AUTHORIZATION_DENIED')).never
    get :index, session: set_session_user(@user)
    assert_response :success
  end
end

class SecurityRejectionEventsFloodMetaTest < ActiveSupport::TestCase
  test 'control characters in path metadata are sanitized by SecurityEvent' do
    dirty = "admin\r\nCSRF_REJECTED\tstatus=SUCCESS"
    clean = Foreman::SecurityEvent.sanitize(dirty)
    refute_includes clean, "\n"
    refute_includes clean, "\r"
  end
end
