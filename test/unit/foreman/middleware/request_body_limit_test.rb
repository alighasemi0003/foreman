# frozen_string_literal: true

require 'test_helper'

class Foreman::Middleware::RequestBodyLimitTest < ActiveSupport::TestCase
  setup do
    @app_status = 200
    @app = lambda do |env|
      # Force full body read like Rails param parsing.
      env['rack.input'].read
      [@app_status, { 'Content-Type' => 'text/plain' }, ['ok']]
    end
    @middleware = Foreman::Middleware::RequestBodyLimit.new(@app)
  end

  def env_for(path, body:, method: 'POST', content_length: :auto)
    input = StringIO.new(body)
    length = content_length == :auto ? body.bytesize.to_s : content_length
    opts = { method: method, input: input, 'CONTENT_TYPE' => 'application/json' }
    opts['CONTENT_LENGTH'] = length unless length.nil?
    Rack::MockRequest.env_for(path, opts)
  end

  test 'small body succeeds' do
    status, = @middleware.call(env_for('/api/v2/hosts', body: '{"a":1}'))
    assert_equal 200, status
  end

  test 'content_length above default limit returns 413 without reading forever' do
    oversized = Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES + 1
    status, headers, body = @middleware.call(
      env_for('/api/v2/hosts', body: 'x', content_length: oversized.to_s)
    )
    assert_equal 413, status
    assert_match(%r{application/json}, headers['Content-Type'])
    assert_match(/no-store/, headers['Cache-Control'])
    payload = JSON.parse(body.join)
    assert_match(/too large/i, payload.dig('error', 'message'))
    refute_match(/password|token|secret/i, body.join)
  end

  test 'streamed body above limit returns 413' do
    # Claim a small Content-Length but actually deliver more than the limit.
    limit = Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES
    body = 'y' * (limit + 100)
    status, = @middleware.call(
      env_for('/api/graphql', body: body, content_length: '10')
    )
    assert_equal 413, status
  end

  test 'missing content_length still enforces on read' do
    limit = Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES
    body = 'z' * (limit + 50)
    status, = @middleware.call(
      env_for('/users/login', body: body, content_length: nil)
    )
    assert_equal 413, status
  end

  test 'facts path allows up to facts limit' do
    body = 'f' * (Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES + 100)
    status, = @middleware.call(env_for('/api/v2/hosts/facts', body: body))
    assert_equal 200, status
  end

  test 'facts path rejects above facts limit' do
    oversized = Foreman::UploadSecurity::MAX_FACTS_BODY_BYTES + 1
    status, = @middleware.call(
      env_for('/api/v2/hosts/facts', body: 'x', content_length: oversized.to_s)
    )
    assert_equal 413, status
  end

  test 'config_reports path uses report limit' do
    body = 'r' * (Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES + 100)
    status, = @middleware.call(env_for('/api/v2/config_reports', body: body))
    assert_equal 200, status

    oversized = Foreman::UploadSecurity::MAX_CONFIG_REPORT_BODY_BYTES + 1
    status, = @middleware.call(
      env_for('/api/v2/config_reports', body: 'x', content_length: oversized.to_s)
    )
    assert_equal 413, status
  end

  test 'GET requests are not limited' do
    huge = 'h' * (Foreman::UploadSecurity::MAX_DEFAULT_REQUEST_BODY_BYTES + 10)
    status, = @middleware.call(env_for('/users/login', body: huge, method: 'GET'))
    assert_equal 200, status
  end
end
