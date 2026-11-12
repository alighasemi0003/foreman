# frozen_string_literal: true

require 'fileutils'

# F-021: safe lifecycle for PID files, Puma state, Unix sockets, and test-only
# reporter artifacts under an application tmp root.
#
# No Rails dependency — usable from container entrypoint before boot.
# Does not kill processes. Does not follow symlinks. Does not wipe tmp/.
#
# Cache orphans remain F-020 (Foreman::TempCacheLifecycle).
module Foreman
  module RuntimeStateLifecycle
    DEFAULT_TEST_ARTIFACT_MAX_AGE = 24 * 60 * 60 # seconds (no ActiveSupport here)
    TEST_ARTIFACT_PREFIX = 'foreman_minitest_reporters_'.freeze
    OUR_CMD_HINTS = [%r{puma}i, %r{rails\s+server}i, %r{bin/rails}i, %r{rackup}i].freeze

    module_function

    # Pre-start / ops: remove stale PID/state/sockets from a previous crash.
    # Pass current_pid of the new process only when it already owns the files
    # (normally omit during entrypoint — previous instance is gone).
    def prestart_cleanup!(root:, current_pid: nil)
      root = expand_root!(root)
      ensure_runtime_directories!(root)

      report = empty_report('prestart', root)
      report.merge!(cleanup_stale_pid_files!(root: root, current_pid: current_pid))
      report.merge!(cleanup_stale_sockets!(root: root, preserve_active: true))
      report.merge!(cleanup_stale_puma_state!(root: root, current_pid: current_pid))
      report.merge!(cleanup_test_reporter_artifacts!(root: root))
      log_report(report)
      report
    end

    # In-process maintenance after boot: never remove live PID/state/sockets for
    # this process; only tighten dirs and age out test reporter files.
    def runtime_maintenance!(root:, current_pid: Process.pid)
      root = expand_root!(root)
      ensure_runtime_directories!(root)

      report = empty_report('runtime', root)
      report.merge!(cleanup_test_reporter_artifacts!(root: root))
      # Re-check foreign/stale PIDs only — never unlink our own.
      report.merge!(cleanup_stale_pid_files!(root: root, current_pid: current_pid))
      report.merge!(cleanup_stale_sockets!(root: root, preserve_active: true))
      harden_permissions!(root)
      log_report(report)
      report
    end

    def ensure_runtime_directories!(root)
      root = expand_root!(root)
      FileUtils.mkdir_p(File.join(root, 'pids'), mode: 0o0750)
      FileUtils.mkdir_p(File.join(root, 'sockets'), mode: 0o0750)
      FileUtils.mkdir_p(File.join(root, 'test'), mode: 0o0750)
      begin
        File.chmod(0o0750, File.join(root, 'pids'))
        File.chmod(0o0750, File.join(root, 'sockets'))
        File.chmod(0o0750, File.join(root, 'test'))
      rescue Errno::EPERM, Errno::EACCES
        # Best-effort when running as non-owner.
      end
      true
    end

    def cleanup_stale_pid_files!(root:, current_pid: nil)
      pids_dir = File.join(root, 'pids')
      removed = 0
      preserved = 0
      skipped = 0
      return { pid_removed: 0, pid_preserved: 0, pid_skipped: 0 } unless File.directory?(pids_dir)

      Dir.children(pids_dir).each do |name|
        path = File.join(pids_dir, name)
        unless safe_plain_file?(path, root)
          skipped += 1
          next
        end

        raw = File.read(path).to_s.strip
        pid = Integer(raw, 10)
        if current_pid && pid == current_pid.to_i
          preserved += 1
          next
        end

        if process_alive?(pid) && process_looks_like_ours?(pid)
          preserved += 1
          next
        end

        # Dead process, or live PID recycled to an unrelated binary — drop the file only.
        File.unlink(path)
        removed += 1
      rescue ArgumentError, TypeError
        # Corrupt pid file
        File.unlink(path) if safe_plain_file?(path, root)
        removed += 1
      rescue Errno::ENOENT
        skipped += 1
      rescue StandardError
        skipped += 1
      end

      { pid_removed: removed, pid_preserved: preserved, pid_skipped: skipped }
    end

    def cleanup_stale_sockets!(root:, preserve_active: true)
      socks_dir = File.join(root, 'sockets')
      removed = 0
      preserved = 0
      skipped = 0
      return { socket_removed: 0, socket_preserved: 0, socket_skipped: 0 } unless File.directory?(socks_dir)

      Dir.children(socks_dir).each do |name|
        path = File.join(socks_dir, name)
        unless safe_socket_or_file?(path, root)
          skipped += 1
          next
        end

        if preserve_active && socket_in_use?(path)
          harden_socket_mode(path)
          preserved += 1
          next
        end

        File.unlink(path)
        removed += 1
      rescue Errno::ENOENT
        skipped += 1
      rescue StandardError
        skipped += 1
      end

      { socket_removed: removed, socket_preserved: preserved, socket_skipped: skipped }
    end

    def cleanup_stale_puma_state!(root:, current_pid: nil)
      path = File.join(root, 'puma.state')
      return { state_removed: 0, state_preserved: 0, state_skipped: 1 } unless File.exist?(path)
      return { state_removed: 0, state_preserved: 0, state_skipped: 1 } unless safe_plain_file?(path, root)

      state_pid = read_puma_state_pid(path)
      if state_pid && current_pid && state_pid == current_pid.to_i
        harden_state_mode(path)
        return { state_removed: 0, state_preserved: 1, state_skipped: 0 }
      end
      if state_pid && process_alive?(state_pid) && process_looks_like_ours?(state_pid)
        harden_state_mode(path)
        return { state_removed: 0, state_preserved: 1, state_skipped: 0 }
      end

      File.unlink(path)
      { state_removed: 1, state_preserved: 0, state_skipped: 0 }
    rescue Errno::ENOENT
      { state_removed: 0, state_preserved: 0, state_skipped: 1 }
    rescue StandardError
      { state_removed: 0, state_preserved: 0, state_skipped: 1 }
    end

    def cleanup_test_reporter_artifacts!(root:, max_age: DEFAULT_TEST_ARTIFACT_MAX_AGE)
      removed = 0
      preserved = 0
      skipped = 0
      cutoff = Time.now - max_age

      candidates = []
      # Legacy location (Rails.root/tmp) and isolated tmp/test/
      [root, File.join(root, 'test')].each do |dir|
        next unless File.directory?(dir)

        Dir.children(dir).each do |name|
          next unless name.start_with?(TEST_ARTIFACT_PREFIX)

          candidates << File.join(dir, name)
        end
      end

      candidates.each do |path|
        unless safe_plain_file?(path, root)
          skipped += 1
          next
        end
        if File.mtime(path) > cutoff
          preserved += 1
          next
        end
        File.unlink(path)
        removed += 1
      rescue Errno::ENOENT
        skipped += 1
      rescue StandardError
        skipped += 1
      end

      { test_artifact_removed: removed, test_artifact_preserved: preserved, test_artifact_skipped: skipped }
    end

    def process_alive?(pid)
      return false if pid.nil? || pid.to_i <= 0

      Process.kill(0, pid.to_i)
      true
    rescue Errno::ESRCH
      false
    rescue Errno::EPERM
      # Exists but not killable by us — treat as alive to avoid deleting active state.
      true
    end

    def process_looks_like_ours?(pid)
      cmd = read_cmdline(pid)
      return false if cmd.nil? || cmd.empty?

      OUR_CMD_HINTS.any? { |re| cmd.match?(re) }
    end

    def read_cmdline(pid)
      File.read("/proc/#{pid.to_i}/cmdline").tr("\0", ' ').strip
    rescue Errno::ENOENT, Errno::EACCES
      # Fallback for non-Linux: do not claim ownership.
      nil
    end

    def read_puma_state_pid(path)
      content = File.read(path)
      if (m = content.match(/^\s*pid:\s*(\d+)\s*$/))
        return m[1].to_i
      end
      if (m = content.match(/"pid"\s*:\s*(\d+)/))
        return m[1].to_i
      end
      nil
    end

    def socket_in_use?(path)
      # Linux: presence in /proc/net/unix or a successful non-blocking connect by peer
      # is enough. Prefer inode scan of /proc/*/fd (no connect side effects).
      return true if proc_fd_references_path?(path)

      # Fallback: try connecting; ECONNREFUSED / ENOENT ⇒ unused
      require 'socket'
      UNIXSocket.new(path).close
      true
    rescue Errno::ECONNREFUSED, Errno::ENOENT, Errno::ECONNRESET
      false
    rescue Errno::EACCES, Errno::EPERM
      true
    rescue StandardError
      # Conservative: if unsure, preserve.
      true
    end

    def proc_fd_references_path?(path)
      real = begin
        File.realpath(path)
      rescue StandardError
        path
      end
      Dir.glob('/proc/[0-9]*/fd/*').any? do |fd|
        target = File.readlink(fd)
        target == real || target.end_with?(File.basename(path))
      rescue Errno::ENOENT, Errno::EACCES, Errno::EINVAL
        false
      end
    end

    def harden_permissions!(root)
      ensure_runtime_directories!(root)
      state = File.join(root, 'puma.state')
      harden_state_mode(state) if File.file?(state) && !File.symlink?(state)
      sock = File.join(root, 'sockets', 'pumactl.sock')
      harden_socket_mode(sock) if File.socket?(sock) && !File.symlink?(sock)
    end

    def harden_state_mode(path)
      File.chmod(0o0640, path)
    rescue Errno::EPERM, Errno::EACCES, Errno::ENOENT
      nil
    end

    def harden_socket_mode(path)
      File.chmod(0o0660, path)
    rescue Errno::EPERM, Errno::EACCES, Errno::ENOENT
      nil
    end

    def safe_plain_file?(path, root)
      return false if File.symlink?(path)
      return false unless File.file?(path)

      contained_under?(path, root)
    end

    def safe_socket_or_file?(path, root)
      return false if File.symlink?(path)
      return false unless File.socket?(path) || File.file?(path)

      contained_under?(path, root)
    end

    def contained_under?(path, root)
      real_root = File.realpath(root)
      real = File.realpath(path)
      real == real_root || real.start_with?(real_root + File::SEPARATOR)
    rescue Errno::ENOENT
      # For sockets, realpath may fail on some systems — use expand_path containment.
      exp_root = File.expand_path(root)
      exp = File.expand_path(path)
      exp == exp_root || exp.start_with?(exp_root + File::SEPARATOR)
    end

    def expand_root!(root)
      path = File.expand_path(root.to_s)
      raise ArgumentError, "runtime root missing: #{path}" unless File.directory?(path)

      path
    end

    def empty_report(source, root)
      {
        source: source,
        root: root,
        pid_removed: 0,
        pid_preserved: 0,
        pid_skipped: 0,
        socket_removed: 0,
        socket_preserved: 0,
        socket_skipped: 0,
        state_removed: 0,
        state_preserved: 0,
        state_skipped: 0,
        test_artifact_removed: 0,
        test_artifact_preserved: 0,
        test_artifact_skipped: 0,
      }
    end

    def log_report(report)
      msg = "F021_RUNTIME_CLEANUP source=#{report[:source]} " \
            "pid_removed=#{report[:pid_removed]} pid_preserved=#{report[:pid_preserved]} " \
            "socket_removed=#{report[:socket_removed]} socket_preserved=#{report[:socket_preserved]} " \
            "state_removed=#{report[:state_removed]} state_preserved=#{report[:state_preserved]} " \
            "test_removed=#{report[:test_artifact_removed]}"
      if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
        Rails.logger.info(msg)
      else
        warn(msg)
      end
    end
  end
end
