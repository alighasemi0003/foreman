# frozen_string_literal: true

require 'test_helper'

# Browser-session CSRF coverage for Rails RequestForgeryProtection as used by Foreman.
class CsrfProtectionTest < ActionController::TestCase
  tests UsersController

  setup do
    ActionController::Base.allow_forgery_protection = true
    @password = 'secret'
    @admin = users(:admin)
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'POST logout without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :logout, session: set_session_user
    end
  end

  test 'POST logout with invalid CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :logout, params: { authenticity_token: 'totally-invalid-token' }, session: set_session_user
    end
  end

  test 'POST logout with valid CSRF token is accepted' do
    token = @controller.send(:form_authenticity_token)
    post :logout, params: { authenticity_token: token }, session: set_session_user
    assert_response :redirect
    assert_redirected_to '/users/login'
  end

  test 'POST login without CSRF token is rejected' do
    post :login, params: { login: { login: @admin.login, password: @password } }
    assert_redirected_to login_users_path
    assert_nil session[:user]
  end

  test 'POST login with valid CSRF token is accepted' do
    token = @controller.send(:form_authenticity_token)
    post :login, params: {
      authenticity_token: token,
      login: { login: @admin.login, password: @password },
    }
    assert_response :redirect
    assert_equal @admin.id, session[:user]
  end

  test 'CSRF token from a different session secret is rejected' do
    token = @controller.send(:form_authenticity_token)
    @request.session[:_csrf_token] = SecureRandom.urlsafe_base64(32)

    assert_raises ActionController::InvalidAuthenticityToken do
      post :logout, params: { authenticity_token: token }, session: set_session_user
    end
  end

  test 'PATCH user update without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      patch :update,
            params: { id: @admin.id, user: { firstname: 'Changed' } },
            session: set_session_user
    end
  end
end

class HostsCsrfProtectionTest < ActionController::TestCase
  tests HostsController

  setup do
    ActionController::Base.allow_forgery_protection = true
    as_admin do
      @host = FactoryBot.create(:host, :managed)
      @host.update_column(:build, true)
    end
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'PUT cancelBuild without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      put :cancelBuild, params: { id: @host.to_param, format: :json }, session: set_session_user
    end
  end

  test 'DELETE destroy without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      delete :destroy, params: { id: @host.to_param, format: :json }, session: set_session_user
    end
  end

  test 'PUT cancelBuild with valid CSRF token is accepted' do
    token = @controller.send(:form_authenticity_token)
    put :cancelBuild,
        params: { id: @host.to_param, authenticity_token: token, format: :json },
        session: set_session_user
    assert_includes [200, 302], @response.status
    refute @host.reload.build
  end
end

class ApiGraphqlCsrfProtectionTest < ActionController::TestCase
  tests Api::GraphqlController

  setup do
    ActionController::Base.allow_forgery_protection = true
    User.current = nil
    reset_api_credentials
    @user = users(:admin)
    @user.update_column(:has_active_session, true)
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
    User.current = nil
  end

  # ApiCsrfProtection defaults to :null_session — forged browser-session requests
  # must not execute GraphQL as the session user.
  test 'GraphQL with UI session and missing CSRF token does not authorize as session user' do
    post :execute,
         params: { query: '{ currentUser { login } }' },
         session: { user: @user.id }

    body = ActiveSupport::JSON.decode(@response.body)
    assert_nil body.dig('data', 'currentUser'),
               "CSRF failure must null the session for the request; got #{body.inspect}"
  end

  test 'GraphQL with UI session and valid CSRF token authorizes as session user' do
    token = @controller.send(:form_authenticity_token)
    request.headers['X-CSRF-Token'] = token

    post :execute,
         params: { query: '{ currentUser { login } }', authenticity_token: token },
         session: { user: @user.id }

    assert_response :success
    body = ActiveSupport::JSON.decode(@response.body)
    assert_equal @user.login, body.dig('data', 'currentUser', 'login'), body.inspect
  end

  test 'GraphQL with Basic Auth API session does not require CSRF token' do
    request.env['HTTP_AUTHORIZATION'] =
      ActionController::HttpAuthentication::Basic.encode_credentials(@user.login, 'secret')

    post :execute, params: { query: '{ currentUser { login } }' }
    assert_response :success
    assert session[:api_authenticated_session]
    body = ActiveSupport::JSON.decode(@response.body)
    assert_equal @user.login, body.dig('data', 'currentUser', 'login'), body.inspect
  end
end

class ApiSessionCsrfProtectionTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    ActionController::Base.allow_forgery_protection = true
    User.current = nil
    reset_api_credentials
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'API mutating request with UI session cookie and no CSRF token is rejected' do
    # GET is not CSRF-checked by Rails; use a state-changing verb.
    post :create, params: { host: { name: 'csrf-test.example.com' } }, session: set_session_user
    assert_response :unauthorized
  end

  test 'API request authenticated via Basic Auth does not require CSRF' do
    set_basic_auth(users(:admin), 'secret')
    get :index
    assert_response :success
    assert session[:api_authenticated_session]
  end
end

class LocationsTaxonomyCsrfTest < ActionController::TestCase
  tests LocationsController

  setup do
    ActionController::Base.allow_forgery_protection = true
    @location = taxonomies(:location1)
    @request.env['HTTP_REFERER'] = root_url
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'GET select is not a recognized route' do
    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path(
        "/locations/#{@location.to_param}/select",
        method: :get
      )
    end
  end

  test 'POST select without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :select, params: { id: @location.id }, session: set_session_user
    end
  end

  test 'POST select with valid CSRF token changes session location' do
    token = @controller.send(:form_authenticity_token)
    post :select,
         params: { id: @location.id, authenticity_token: token },
         session: set_session_user
    assert_equal @location.id, session[:location_id]
    assert_redirected_to root_url
  end

  test 'POST clear without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :clear, session: set_session_user.merge(location_id: @location.id)
    end
  end

  test 'POST clear with valid CSRF token clears session location' do
    token = @controller.send(:form_authenticity_token)
    post :clear,
         params: { authenticity_token: token },
         session: set_session_user.merge(location_id: @location.id)
    assert_equal '', session[:location_id]
    assert_nil Location.current
    assert_redirected_to root_url
  end

  test 'POST select with rotated session CSRF secret is rejected' do
    token = @controller.send(:form_authenticity_token)
    @request.session[:_csrf_token] = SecureRandom.urlsafe_base64(32)
    assert_raises ActionController::InvalidAuthenticityToken do
      post :select, params: { id: @location.id, authenticity_token: token }, session: set_session_user
    end
  end
end

class OrganizationsTaxonomyCsrfTest < ActionController::TestCase
  tests OrganizationsController

  setup do
    ActionController::Base.allow_forgery_protection = true
    @organization = taxonomies(:organization1)
    @request.env['HTTP_REFERER'] = root_url
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'GET select is not a recognized route' do
    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path(
        "/organizations/#{@organization.to_param}/select",
        method: :get
      )
    end
  end

  test 'POST select without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :select, params: { id: @organization.id }, session: set_session_user
    end
  end

  test 'POST select with valid CSRF token changes session organization' do
    token = @controller.send(:form_authenticity_token)
    post :select,
         params: { id: @organization.id, authenticity_token: token },
         session: set_session_user
    assert_equal @organization.id, session[:organization_id]
    assert_redirected_to root_url
  end

  test 'POST clear without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :clear, session: set_session_user.merge(organization_id: @organization.id)
    end
  end

  test 'POST clear with valid CSRF token clears session organization' do
    token = @controller.send(:form_authenticity_token)
    post :clear,
         params: { authenticity_token: token },
         session: set_session_user.merge(organization_id: @organization.id)
    assert_equal '', session[:organization_id]
    assert_nil Organization.current
    assert_redirected_to root_url
  end
end

class BuildPxeDefaultCsrfTest < ActionController::TestCase
  tests ProvisioningTemplatesController

  setup do
    ActionController::Base.allow_forgery_protection = true
    @request.env['HTTP_REFERER'] = provisioning_templates_path
  end

  teardown do
    ActionController::Base.allow_forgery_protection = false
  end

  test 'GET build_pxe_default is not a recognized route' do
    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path('/provisioning_templates/build_pxe_default', method: :get)
    end
  end

  test 'POST build_pxe_default without CSRF token is rejected' do
    assert_raises ActionController::InvalidAuthenticityToken do
      post :build_pxe_default, session: set_session_user
    end
  end
end
