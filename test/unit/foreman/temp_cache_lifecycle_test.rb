# frozen_string_literal: true

require 'test_helper'
require 'fileutils'

class Foreman::TempCacheLifecycleTest < ActiveSupport::TestCase
  setup do
    @root = Dir.mktmpdir('foreman-f020-tmp')
    FileUtils.mkdir_p(File.join(@root, 'pids'))
    FileUtils.mkdir_p(File.join(@root, 'sockets'))
    FileUtils.mkdir_p(File.join(@root, 'cache'))
    File.write(File.join(@root, 'secret_token'), 'x' * 32)
    File.write(File.join(@root, 'restart.txt'), '')
    File.write(File.join(@root, 'puma.state'), '{}')

    Foreman::TempCacheLifecycle.stubs(:tmp_root).returns(Pathname.new(@root))
  end

  teardown do
    FileUtils.rm_rf(@root) if @root && File.directory?(@root)
  end

  test 'cleanup removes aged orphan tempfiles under tmp root only' do
    orphan = File.join(@root, 'cert20260101-1-abc')
    File.write(orphan, 'SENSITIVE_PEM')
    File.utime(Time.now - 2.hours, Time.now - 2.hours, orphan)

    fresh = File.join(@root, 'fresh20260101-1-xyz')
    File.write(fresh, 'active')

    stats = Foreman::TempCacheLifecycle.cleanup_orphaned_tempfiles!(max_age: 1.hour)

    refute File.exist?(orphan), 'aged orphan should be removed'
    assert File.exist?(fresh), 'fresh tempfile must remain'
    assert File.exist?(File.join(@root, 'secret_token'))
    assert File.directory?(File.join(@root, 'pids'))
    assert File.directory?(File.join(@root, 'sockets'))
    assert_operator stats[:orphan_removed], :>=, 1
  end

  test 'cleanup does not follow or delete symlink escape targets' do
    outside = Dir.mktmpdir('foreman-f020-outside')
    begin
      target = File.join(outside, 'important.dat')
      File.write(target, 'KEEP')
      link = File.join(@root, 'escape_link')
      File.symlink(target, link)
      File.utime(Time.now - 2.hours, Time.now - 2.hours, link) rescue nil

      Foreman::TempCacheLifecycle.cleanup_orphaned_tempfiles!(max_age: 1.hour)

      assert File.exist?(target), 'symlink target outside tmp must be preserved'
      assert File.symlink?(link), 'symlink entry itself is skipped not followed'
    ensure
      FileUtils.rm_rf(outside)
    end
  end

  test 'resolve_cleanup_root rejects paths outside tmp' do
    assert_raises(ArgumentError) do
      Foreman::TempCacheLifecycle.resolve_cleanup_root('/tmp')
    end
  end

  test 'file store cleanup is skipped for non-FileStore backends' do
    result = Foreman::TempCacheLifecycle.cleanup_file_store_cache!
    # test env uses memory_store
    refute result[:expired_cleanup]
    assert_match(/skipped_non_file_store/, result[:note])
  end

  test 'file store expired cleanup and hard prune on isolated FileStore' do
    cache_dir = File.join(@root, 'cache')
    store = ActiveSupport::Cache::FileStore.new(cache_dir)

    store.write('alive', 'v1', expires_in: 1.hour)
    store.write('expire_soon', 'v2', expires_in: 1.second)
    sleep 1.1
    store.cleanup

    stale = File.join(cache_dir, 'stale_manual_file')
    File.write(stale, 'old')
    File.utime(Time.now - 10.days, Time.now - 10.days, stale)

    Foreman::TempCacheLifecycle.stubs(:file_store?).returns(true)
    Foreman::TempCacheLifecycle.stubs(:file_store_cache_path).returns(cache_dir)
    ActiveSupport::Cache::FileStore.any_instance.stubs(:cache_path).returns(cache_dir)
    Rails.stubs(:cache).returns(store)

    report = Foreman::TempCacheLifecycle.cleanup_file_store_cache!(prune_stale: true, hard_max_age: 7.days)

    assert report[:expired_cleanup]
    refute File.exist?(stale), 'hard-aged file under FileStore path removed'
    assert_equal 'v1', store.read('alive'), 'active unexpired cache entry remains'
  end

  test 'periodic cleanup report includes backend and does not touch redis keys counter as delete' do
    report = Foreman::TempCacheLifecycle.periodic_cleanup!(orphan_max_age: 1.hour)
    assert_equal 'periodic', report[:source]
    assert report.key?(:cache_backend)
    assert_equal 0, report[:redis_keys_touched]
  end

  test 'startup cleanup can be forced in test with isolated root' do
    orphan = File.join(@root, 'oldtmp-left')
    File.write(orphan, 'x')
    File.utime(Time.now - 3.hours, Time.now - 3.hours, orphan)

    report = Foreman::TempCacheLifecycle.startup_cleanup!(orphan_max_age: 1.hour, force: true)
    refute File.exist?(orphan)
    assert_operator report[:orphan_removed], :>=, 1
  end
end
