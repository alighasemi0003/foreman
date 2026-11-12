# frozen_string_literal: true

require 'test_helper'

class OutputClassificationHostYamlTest < ActionController::TestCase
  tests HostsController

  setup do
    @secret = 'synth-f013-secret-001'
    as_admin do
      @host = FactoryBot.create(:host, :location => taxonomies(:location1),
        :organization => taxonomies(:organization1))
      @host.host_parameters.create!(name: 'f013_secret', value: @secret, hidden_value: true)
    end
    Setting[:output_classification_enabled] = true
  end

  test 'yaml export includes classification comment and confidential header when redacted' do
    setup_user 'view', 'hosts'
    setup_user 'view', 'params'
    setup_user 'view', 'locations'
    setup_user 'view', 'organizations'
    get :show, params: { id: @host.to_param, format: 'yaml' }, session: set_session_user(@one)
    assert_response :success
    assert_equal 'confidential', @response.headers['X-Foreman-Classification']
    assert_match(/# X-Foreman-Classification: confidential/, @response.body)
    parsed = YAML.safe_load(@response.body)
    assert_kind_of Hash, parsed
    assert_equal HiddenValue::HIDDEN_VALUE, parsed.dig('parameters', 'f013_secret')
    refute_includes @response.body, @secret
  end

  test 'client cannot downgrade yaml classification via params' do
    setup_user 'view', 'hosts'
    setup_user 'view', 'params'
    setup_user 'view', 'locations'
    setup_user 'view', 'organizations'
    get :show, params: {
      id: @host.to_param, format: 'yaml',
      classification: 'public', output_classification: 'public',
    }, session: set_session_user(@one)
    assert_response :success
    assert_equal 'confidential', @response.headers['X-Foreman-Classification']
  end

  test 'admin yaml with secrets is restricted and still labeled' do
    get :show, params: { id: @host.to_param, format: 'yaml' }, session: set_session_user
    assert_response :success
    assert_equal 'restricted', @response.headers['X-Foreman-Classification']
    assert_match(/# X-Foreman-Classification: restricted/, @response.body)
    assert_includes @response.body, @secret
  end
end

class OutputClassificationHostCsvTest < ActionController::TestCase
  tests HostsController

  setup do
    as_admin { FactoryBot.create(:host) }
    Setting[:output_classification_enabled] = true
  end

  test 'csv export is labeled internal and remains parseable' do
    get :index, params: { format: 'csv' }, session: set_session_user
    assert_response :success
    assert_equal 'internal', @response.headers['X-Foreman-Classification']
    chunks = []
    buf = response.stream.instance_variable_get(:@buf)
    if buf
      loop { chunks << buf.next }
    else
      chunks << @response.body
    end
    body = chunks.join
    first_line = body.lines.first.to_s
    refute_match(/\A#/, first_line)
    refute_match(/X-Foreman-Classification/i, first_line)
    rows = CSV.parse(body)
    assert_operator rows.size, :>=, 1
  end
end

class OutputClassificationEncApiTest < ActionController::TestCase
  tests Api::V2::HostsController

  setup do
    @secret = 'synth-f013-enc-secret'
    as_admin do
      @host = FactoryBot.create(:host)
      @host.host_parameters.create!(name: 'f013_enc_secret', value: @secret, hidden_value: true)
    end
    Setting[:output_classification_enabled] = true
  end

  test 'enc json keeps schema and sets confidential header for view_hosts' do
    setup_user 'view', 'hosts'
    setup_user 'view', 'params'
    setup_user 'view', 'locations'
    setup_user 'view', 'organizations'
    get :enc, params: { id: @host.to_param },
        session: set_session_user.merge(user: @one.id)
    assert_response :success
    body = JSON.parse(@response.body)
    assert body.key?('data')
    refute body.key?('classification')
    assert_equal 'confidential', @response.headers['X-Foreman-Classification']
    assert_equal HiddenValue::HIDDEN_VALUE, body.dig('data', 'parameters', 'f013_enc_secret')
  end

  test 'enc with edit_params and secrets revealed is restricted' do
    get :enc, params: { id: @host.to_param, show_hidden_parameters: true },
        session: set_session_user
    assert_response :success
    assert_equal 'restricted', @response.headers['X-Foreman-Classification']
    body = JSON.parse(@response.body)
    assert_equal @secret, body.dig('data', 'parameters', 'f013_enc_secret')
  end
end

class OutputClassificationPrintLayoutTest < ActionController::TestCase
  tests DashboardController

  setup do
    Setting[:output_classification_enabled] = true
  end

  test 'authenticated html includes print classification banner and headers' do
    get :index, session: set_session_user
    assert_response :success
    assert_equal 'internal', @response.headers['X-Foreman-Classification']
    assert_includes @response.body, 'foreman-classification-print'
    assert_includes @response.body, 'Classification:'
    assert_match(/name="foreman-classification" content="internal"/, @response.body)
  end
end
