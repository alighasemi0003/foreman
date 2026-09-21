# frozen_string_literal: true

require 'test_helper'

# Production-like exception handling: no internal details leaked to clients.
class SecurityExceptionHandlingUiController < ApplicationController
  skip_before_action :require_login, :check_user_enabled,
                     :set_taxonomy, :require_mail,
                     :check_empty_taxonomy, :authorize, :session_expiry,
                     :update_activity_time, raise: false

  def boom
    raise StandardError, 'SUPER_SECRET_INTERNAL_ERROR_123'
  end
end

class SecurityExceptionHandlingApiController < Api::V2::BaseController
  skip_before_action :authorize, :authenticate, :set_taxonomy, raise: false

  def boom
    raise StandardError, 'SUPER_SECRET_INTERNAL_ERROR_123'
  end

  def sql_boom
    raise ActiveRecord::StatementInvalid, 'PG::UndefinedTable: ERROR: relation "secret_table_xyz" does not exist LINE 1: SELECT * FROM secret_table_xyz'
  end

  def action_permission
    :view
  end
end

class SecurityExceptionHandlingTest < ActionController::TestCase
  SECRET = 'SUPER_SECRET_INTERNAL_ERROR_123'
  SQL_MARKER = 'secret_table_xyz'
  SAFE_MSG = Foreman::ClientError.internal_server_error_message

  context 'UI unexpected exception (production-like)' do
    tests SecurityExceptionHandlingUiController

    setup do
      @prev_local = Rails.application.config.consider_all_requests_local
      Rails.application.config.consider_all_requests_local = false
    end

    teardown do
      Rails.application.config.consider_all_requests_local = @prev_local
    end

    test 'UI 500 does not expose internal exception message or stack' do
      with_routing do |set|
        set.draw do
          get 'security_ui_boom' => 'security_exception_handling_ui#boom'
        end
        Foreman::Logging.expects(:exception).at_least_once
        get :boom
      end
      assert_response :internal_server_error
      refute_includes @response.body, SECRET
      refute_match(/backtrace|app\/controllers|\/home\/|gems\//i, @response.body)
      assert_match(/Oops|Internal Server Error/i, @response.body)
    end
  end

  context 'API unexpected exception' do
    tests SecurityExceptionHandlingApiController

    test 'API 500 returns generic JSON without internal message' do
      with_routing do |set|
        set.draw do
          scope :api do
            get 'security_api_boom' => 'security_exception_handling_api#boom'
          end
        end
        Foreman::Logging.expects(:exception).at_least_once
        get :boom
      end
      assert_response :internal_server_error
      body = JSON.parse(@response.body)
      assert_equal SAFE_MSG, body.dig('error', 'message')
      refute_includes @response.body, SECRET
      refute_includes @response.body, 'backtrace'
    end

    test 'API database exception does not expose SQL details' do
      with_routing do |set|
        set.draw do
          scope :api do
            get 'security_api_sql_boom' => 'security_exception_handling_api#sql_boom'
          end
        end
        Foreman::Logging.expects(:exception).at_least_once
        get :sql_boom
      end
      assert_response :internal_server_error
      refute_includes @response.body, SQL_MARKER
      refute_includes @response.body, 'PG::'
      refute_includes @response.body, 'SELECT'
      assert_equal SAFE_MSG, JSON.parse(@response.body).dig('error', 'message')
    end
  end
end

class SecurityExceptionHandlingApiNotFoundTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    as_admin { User.current = users(:admin) }
  end

  test 'API missing host returns 404 without stack trace' do
    get :show, params: { id: 'nonexistent-host-xyz-99999' }
    assert_response :not_found
    refute_match(/backtrace|app\/models|PG::/i, @response.body)
    body = JSON.parse(@response.body)
    assert body['error'].present?
  end

  test 'API validation error returns client-safe response' do
    post :create, params: { host: { name: '' } }
    assert_includes [400, 422], @response.status
    refute_match(/backtrace|\/home\/|gems\//i, @response.body)
  end
end

class SecurityExceptionHandlingGraphqlTest < ActiveSupport::TestCase
  SECRET = 'SUPER_SECRET_INTERNAL_ERROR_123'

  test 'GraphQL unexpected exception is sanitized and logged' do
    Resolvers::User::Current.class_eval do
      alias_method :resolve_without_security_test, :resolve
      define_method(:resolve) { raise StandardError, SECRET }
    end

    begin
      Foreman::Logging.expects(:exception).at_least_once
      result = ForemanGraphqlSchema.execute(
        '{ currentUser { id } }',
        context: { current_user: users(:admin) }
      )

      assert result['errors'].present?, "expected GraphQL errors, got: #{result.inspect}"
      messages = result['errors'].map { |e| e['message'] }.join("\n")
      refute_includes messages, SECRET
      assert_includes messages, 'Internal Server Error'
      refute_includes result.to_json, 'backtrace'
      refute_includes result.to_json, '/home/'
    ensure
      Resolvers::User::Current.class_eval do
        alias_method :resolve, :resolve_without_security_test
        remove_method :resolve_without_security_test
      end
    end
  end
end

class SecurityExceptionHandlingRoutingTest < ActiveSupport::TestCase
  test 'unknown route returns safe 404 without routing debug' do
    env_config = Rails.application.env_config
    previous = env_config['action_dispatch.show_exceptions']
    previous_detailed = env_config['action_dispatch.show_detailed_exceptions']
    env_config['action_dispatch.show_exceptions'] = true
    env_config['action_dispatch.show_detailed_exceptions'] = false
    begin
      status, _headers, body = Rails.application.call(
        Rack::MockRequest.env_for('/this-route-does-not-exist-xyz-404')
      )
      response_body = +''
      body.each { |chunk| response_body << chunk }
      body.close if body.respond_to?(:close)

      assert_equal 404, status
      refute_match(/Routes \(.*\)|ActionController::RoutingError|Rails\.root|\/home\/aligh/i, response_body)
      refute_match(/SUPER_SECRET|backtrace/i, response_body)
    ensure
      env_config['action_dispatch.show_exceptions'] = previous
      env_config['action_dispatch.show_detailed_exceptions'] = previous_detailed
    end
  end

  test 'production config disables detailed exception pages' do
    # Test env defaults to local; production.rb sets consider_all_requests_local = false
    production_rb = File.read(Rails.root.join('config/environments/production.rb'))
    assert_match(/consider_all_requests_local\s*=\s*false/, production_rb)
  end
end

class SecurityExceptionHandlingProxyTest < ActiveSupport::TestCase
  include Foreman::HttpProxy

  test 'http_proxied_rescue does not embed backtrace in raised message' do
    err = assert_raises(RuntimeError) do
      http_proxied_rescue do
        raise RuntimeError, 'connection refused'
      end
    end
    refute_match(/http_proxy\.rb|app\/lib\/foreman/i, err.message)
    assert_match(/Proxied request failed/, err.message)
    assert_match(/connection refused/, err.message)
  end
end

class SecurityExceptionHandlingFilterParamsTest < ActiveSupport::TestCase
  test 'sensitive parameters are filtered from logs' do
    filters = Rails.application.config.filter_parameters.map(&:to_s)
    %w[password password_confirmation secret token api_key authorization auth_token
       private_key oauth_token refresh_token client_secret access_token cookie session].each do |key|
      assert filters.any? { |f| f.include?(key) }, "expected filter_parameters to include #{key}"
    end

    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    filtered = filter.filter(
      'password' => 's3cret',
      'token' => 'tok123',
      'api_key' => 'key123',
      'authorization' => 'Bearer abc'
    )
    assert_equal '[FILTERED]', filtered['password']
    assert_equal '[FILTERED]', filtered['token']
    assert_equal '[FILTERED]', filtered['api_key']
    assert_equal '[FILTERED]', filtered['authorization']
  end
end

class SecurityExceptionHandlingClientErrorTest < ActiveSupport::TestCase
  test 'client_message keeps Foreman::Exception text' do
    ex = Foreman::Exception.new(N_("Friendly user message"))
    assert_includes Foreman::ClientError.client_message(ex), 'Friendly user message'
  end

  test 'client_message sanitizes generic StandardError' do
    msg = Foreman::ClientError.client_message(StandardError.new('leak me'))
    refute_includes msg, 'leak me'
    assert_includes msg, 'Internal Server Error'
  end
end
