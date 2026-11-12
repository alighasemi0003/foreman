# frozen_string_literal: true

require 'test_helper'
require 'fileutils'
require 'socket'
require 'foreman/runtime_state_lifecycle'

class Foreman::RuntimeStateLifecycleTest < ActiveSupport::TestCase
  setup do
    @root = Dir.mktmpdir('foreman-f021-tmp')
    Foreman::RuntimeStateLifecycle.ensure_runtime_directories!(@root)
  end

  teardown do
    FileUtils.rm_rf(@root) if @root && File.directory?(@root)
  end

  test 'ensure_runtime_directories creates restrictive pids sockets and test dirs' do
    assert File.directory?(File.join(@root, 'pids'))
    assert File.directory?(File.join(@root, 'sockets'))
    assert File.directory?(File.join(@root, 'test'))
    mode = File.stat(File.join(@root, 'pids')).mode & 0o777
    assert_operator mode, :<=, 0o750
  end

  test 'stale pid file for dead process is removed' do
    path = File.join(@root, 'pids', 'server.pid')
    File.write(path, '999999')
    refute Foreman::RuntimeStateLifecycle.process_alive?(999_999)

    stats = Foreman::RuntimeStateLifecycle.cleanup_stale_pid_files!(root: @root)
    refute File.exist?(path)
    assert_equal 1, stats[:pid_removed]
  end

  test 'active pid matching current process is preserved' do
    path = File.join(@root, 'pids', 'server.pid')
    File.write(path, Process.pid.to_s)

    stats = Foreman::RuntimeStateLifecycle.cleanup_stale_pid_files!(root: @root, current_pid: Process.pid)
    assert File.exist?(path)
    assert_equal 1, stats[:pid_preserved]
    assert_equal 0, stats[:pid_removed]
  end

  test 'corrupt pid file is removed' do
    path = File.join(@root, 'pids', 'server.pid')
    File.write(path, 'not-a-pid')
    Foreman::RuntimeStateLifecycle.cleanup_stale_pid_files!(root: @root)
    refute File.exist?(path)
  end

  test 'symlink pid path is skipped and target preserved' do
    outside = Dir.mktmpdir('f021-out')
    begin
      target = File.join(outside, 'keep.pid')
      File.write(target, '1')
      link = File.join(@root, 'pids', 'server.pid')
      File.symlink(target, link)

      Foreman::RuntimeStateLifecycle.cleanup_stale_pid_files!(root: @root)
      assert File.exist?(target)
      assert File.symlink?(link)
    ensure
      FileUtils.rm_rf(outside)
    end
  end

  test 'stale unused socket is removed and active socket preserved' do
    stale = File.join(@root, 'sockets', 'stale.sock')
    File.symlink('/tmp/nonexistent-f021', File.join(@root, 'sockets', 'escape.sock')) rescue nil
    # Create a real bound socket then close it so the path remains as a stale inode
    begin
      server = UNIXServer.new(stale)
      server.close
    rescue Errno::EADDRINUSE
      File.unlink(stale) if File.exist?(stale)
      server = UNIXServer.new(stale)
      server.close
    end
    # Path may remain after close on Linux
    if File.exist?(stale)
      Foreman::RuntimeStateLifecycle.cleanup_stale_sockets!(root: @root, preserve_active: true)
      # After close, connect should fail → removed (or already gone)
      refute File.exist?(stale), 'closed unused socket should be removed'
    end

    active = File.join(@root, 'sockets', 'active.sock')
    File.unlink(active) if File.exist?(active)
    live = UNIXServer.new(active)
    begin
      stats = Foreman::RuntimeStateLifecycle.cleanup_stale_sockets!(root: @root, preserve_active: true)
      assert File.socket?(active), 'live listening socket must remain'
      assert_operator stats[:socket_preserved], :>=, 1
    ensure
      live.close
      File.unlink(active) if File.exist?(active)
    end
  end

  test 'puma state removed when recorded pid is dead' do
    path = File.join(@root, 'puma.state')
    File.write(path, "---\npid: 999999\ncontrol_url: unix:///tmp/x\n")
    stats = Foreman::RuntimeStateLifecycle.cleanup_stale_puma_state!(root: @root)
    refute File.exist?(path)
    assert_equal 1, stats[:state_removed]
  end

  test 'puma state preserved for current pid and hardened' do
    path = File.join(@root, 'puma.state')
    File.write(path, "---\npid: #{Process.pid}\ncontrol_url: unix:///tmp/x\n")
    File.chmod(0o0644, path)
    stats = Foreman::RuntimeStateLifecycle.cleanup_stale_puma_state!(root: @root, current_pid: Process.pid)
    assert File.exist?(path)
    assert_equal 1, stats[:state_preserved]
    assert_equal 0o0640, File.stat(path).mode & 0o777
  end

  test 'aged test reporter artifacts removed; fresh kept; legacy and tmp/test paths' do
    legacy = File.join(@root, 'foreman_minitest_reporters_previous_run')
    fresh = File.join(@root, 'test', 'foreman_minitest_reporters_report')
    File.write(legacy, 'old')
    File.utime(Time.now - 48 * 3600, Time.now - 48 * 3600, legacy)
    File.write(fresh, 'new')

    stats = Foreman::RuntimeStateLifecycle.cleanup_test_reporter_artifacts!(root: @root, max_age: 24 * 3600)
    refute File.exist?(legacy)
    assert File.exist?(fresh)
    assert_operator stats[:test_artifact_removed], :>=, 1
    assert_operator stats[:test_artifact_preserved], :>=, 1
  end

  test 'prestart_cleanup report includes counters and does not touch secret_token' do
    File.write(File.join(@root, 'secret_token'), 'x' * 32)
    File.write(File.join(@root, 'pids', 'server.pid'), '999999')
    report = Foreman::RuntimeStateLifecycle.prestart_cleanup!(root: @root)
    assert_equal 'prestart', report[:source]
    assert File.exist?(File.join(@root, 'secret_token'))
    refute File.exist?(File.join(@root, 'pids', 'server.pid'))
    assert_operator report[:pid_removed], :>=, 1
  end

  test 'runtime_maintenance preserves live pid for current process' do
    File.write(File.join(@root, 'pids', 'server.pid'), Process.pid.to_s)
    report = Foreman::RuntimeStateLifecycle.runtime_maintenance!(root: @root, current_pid: Process.pid)
    assert File.exist?(File.join(@root, 'pids', 'server.pid'))
    assert_equal 'runtime', report[:source]
  end
end
