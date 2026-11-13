# frozen_string_literal: true

require 'test_helper'
require 'foreman/middleware/block_source_maps'

class Foreman::Middleware::BlockSourceMapsTest < ActiveSupport::TestCase
  setup do
    @app = ->(_env) { [200, { 'Content-Type' => 'text/plain' }, ['ok']] }
    @mw = Foreman::Middleware::BlockSourceMaps.new(@app)
  end

  test 'blocks webpack js map' do
    status, headers, body = @mw.call('PATH_INFO' => '/webpack/bundle-abc.js.map', 'REQUEST_METHOD' => 'GET')
    assert_equal 404, status
    assert_equal 'blocked', headers['X-Foreman-SourceMap']
    assert_equal ["Not Found\n"], body
  end

  test 'blocks webpack map.gz' do
    status, = @mw.call('PATH_INFO' => '/webpack/bundle-abc.js.map.gz', 'REQUEST_METHOD' => 'GET')
    assert_equal 404, status
  end

  test 'blocks assets path maps' do
    status, = @mw.call('PATH_INFO' => '/assets/application-digest.js.map', 'REQUEST_METHOD' => 'GET')
    assert_equal 404, status
  end

  test 'allows normal webpack js bundles' do
    status, _, body = @mw.call('PATH_INFO' => '/webpack/bundle-abc.js', 'REQUEST_METHOD' => 'GET')
    assert_equal 200, status
    assert_equal ['ok'], body
  end

  test 'allows unrelated paths' do
    status, = @mw.call('PATH_INFO' => '/users/login', 'REQUEST_METHOD' => 'GET')
    assert_equal 200, status
  end
end
