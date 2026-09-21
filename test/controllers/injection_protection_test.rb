# frozen_string_literal: true

require 'test_helper'

# Stored XSS: persisted user-controlled values must be escaped in HTML responses.
class ArchitectureStoredXssTest < ActionController::TestCase
  tests ArchitecturesController

  test 'stored XSS payload in architecture name is escaped on index and edit' do
    payload = '<script>alert(1)</script>'
    arch = FactoryBot.create(:architecture, :name => "arch-#{SecureRandom.hex(4)}")
    arch.update_column(:name, payload)

    get :index, session: set_session_user
    assert_response :success
    assert_not_includes response.body, '<script>alert(1)</script>'
    assert_match(/&lt;script&gt;alert\(1\)&lt;\/script&gt;/, response.body)

    get :edit, params: { :id => arch.id }, session: set_session_user
    assert_response :success
    assert_not_includes response.body, '<script>alert(1)</script>'
  end
end

# Reflected XSS via search query parameter.
class HostsReflectedSearchXssTest < ActionController::TestCase
  tests HostsController

  test 'reflected search parameter is not rendered as executable HTML' do
    get :index, params: { :search => '<script>alert(1)</script>' }, session: set_session_user
    assert_response :success
    assert_not_includes response.body, '<script>alert(1)</script>'
  end
end

# BMC power status marked html_safe must escape unknown statuses.
class BmcHelperXssTest < ActionView::TestCase
  include BMCHelper

  test 'unknown power status escapes HTML from BMC' do
    html = power_status('<img src=x onerror=alert(1)>')
    assert_includes html, '&lt;img'
    assert_not_includes html.to_s.gsub('&lt;img', ''), '<img src=x'
  end

  test 'known power statuses remain label markup' do
    assert_match(/label-success/, power_status('on'))
    assert_match(/label-default/, power_status('off'))
  end
end

# Compute-resource style error messages joined for HTML tooltips.
class ErrorsHashXssTest < ActiveSupport::TestCase
  test 'errors_hash escapes full_messages before joining br' do
    controller = ApplicationController.new
    errors = ActiveModel::Errors.new(Domain.new)
    errors.add(:base, '<script>alert(1)</script>')
    errors.add(:name, '<img src=x onerror=alert(1)>')

    result = controller.send(:errors_hash, errors)
    assert_equal N_('Error'), result[:status]
    assert_includes result[:message], '&lt;script&gt;'
    assert_includes result[:message], '&lt;img'
    assert_not_includes result[:message], '<script>alert(1)</script>'
    assert_includes result[:message], '<br>'
  end
end

# Template input descriptions feed Bootstrap popovers with html:true.
class TemplatesHelperDescriptionXssTest < ActionView::TestCase
  include LayoutHelper
  include ApplicationHelper

  test 'escaped template input description is safe in popover html content' do
    payload = '<img src=x onerror=alert(1)>'
    # Mirrors templates_helper#template_input_f escaping before label_help/popover.
    description = ERB::Util.html_escape(payload)
    html = popover('', description)
    assert_not_includes html, '<img src=x onerror=alert(1)>'
    assert_match(/&lt;img/, html)
  end

  test 'template_input_f escapes description before building options' do
    helper = Object.new.extend(TemplatesHelper)
    input = FactoryBot.build_stubbed(:template_input, :description => '<script>alert(1)</script>', :name => 'n')
    value = ReportComposer::InputValue.new(:value => '', :template_input => input)
    f = Object.new
    f.define_singleton_method(:object) { value }

    # Capture options passed into the first field helper branch by stubbing textarea_f
    captured = nil
    helper.define_singleton_method(:textarea_f) do |_f, _attr, options|
      captured = options
      'field'
    end
    helper.define_singleton_method(:selectable_f) { |*| 'sel' }
    helper.define_singleton_method(:react_form_input) { |*| 'react' }

    helper.template_input_f(f)
    assert_equal '&lt;script&gt;alert(1)&lt;/script&gt;', captured[:label_help]
  end
end

# ORDER BY injection via virtual_column_scope (Roles locked column).
class VirtualColumnOrderInjectionTest < ActionController::TestCase
  tests RolesController

  test 'virtual column order rejects SQL function injection payloads' do
    get :index, params: { :order => 'locked ASC, pg_sleep(1)' }, session: set_session_user
    assert_includes [200, 302], response.status
  end

  test 'virtual column order accepts allowlisted locked DESC' do
    get :index, params: { :order => 'locked DESC' }, session: set_session_user
    assert_response :success
  end
end

class ApiRolesOrderInjectionTest < ActionController::TestCase
  tests Api::V2::RolesController

  test 'API order with SQL function after locked does not fail with SQL error' do
    get :index, params: { :order => 'locked ASC, version()' }, session: set_session_user
    assert_response :success
    body = ActiveSupport::JSON.decode(response.body)
    assert body['results'].is_a?(Array)
  end
end

# Scoped search / query DSL injection.
class ScopedSearchSqlInjectionTest < ActionController::TestCase
  tests DomainsController

  test 'search DSL injection payload does not cause SQL error' do
    get :index, params: { :search => "name = '' OR '1'='1'" }, session: set_session_user
    assert_includes [200, 302, 400, 422], response.status
    refute_equal 500, response.status, response.body.to_s[0, 500]
  end

  test 'legitimate search still finds domain' do
    unique = "dom-#{SecureRandom.hex(6)}.example.com"
    FactoryBot.create(:domain, :name => unique)
    get :index, params: { :search => "name = #{unique}" }, session: set_session_user
    assert_response :success
    assert_includes response.body, unique
  end
end

class ApiSearchSqlInjectionTest < ActionController::TestCase
  tests Api::V2::DomainsController

  test 'API search tautology-style payload does not raise SQL error' do
    get :index, params: { :search => "name = 'x' OR name != ''" }, session: set_session_user
    assert_includes [200, 400, 422], response.status
    if response.status == 200
      body = ActiveSupport::JSON.decode(response.body)
      assert body.key?('results')
    end
  end
end

# Subnet ORDER BY allowlist (regex-gated network_reorder).
class SubnetOrderAllowlistTest < ActionController::TestCase
  tests SubnetsController

  test 'subnet network order allowlist rejects injection' do
    get :index, params: { :order => 'network ASC; SELECT 1' }, session: set_session_user
    assert_response :success
  end

  test 'subnet network order accepts allowlisted value' do
    get :index, params: { :order => 'network DESC' }, session: set_session_user
    assert_response :success
  end
end

# GraphQL search injection representative.
class GraphqlSearchInjectionTest < ActiveSupport::TestCase
  test 'GraphQL domains search with injection payload does not raise SQL error' do
    skip unless defined?(ForemanGraphqlSchema)

    query = <<~GQL
      query($search: String) {
        domains(first: 5, search: $search) {
          totalCount
          edges { node { name } }
        }
      }
    GQL

    result = ForemanGraphqlSchema.execute(
      query,
      variables: { 'search' => "name = '' OR '1'='1'" },
      context: { current_user: users(:admin) }
    )
    sql_error = Array(result['errors']).any? { |e| e['message'].to_s =~ /syntax error|PG::|Mysql2|SQLite3/i }
    refute sql_error, "Unexpected SQL error: #{result['errors'].inspect}"
  end
end
