# frozen_string_literal: true

require 'find'

# F-020: bounded cleanup of Foreman-owned temporary files and regenerable
# FileStore cache artifacts under Rails.root/tmp.
#
# Does not touch: pids/, sockets/, secret_token, logs, DB, Redis data volumes,
# audit archives, or paths outside the resolved tmp root (symlink escape).
#
# RedisCacheStore: key TTL is owned by writers (expires_in). This module does
# not FLUSHDB or delete live Redis keys.
module Foreman
  module TempCacheLifecycle
    DEFAULT_ORPHAN_MAX_AGE = 1.hour
    DEFAULT_FILE_CACHE_EXPIRES_IN = 12.hours
    DEFAULT_FILE_CACHE_HARD_MAX_AGE = 7.days

    # Runtime / persistent artifacts under tmp — F-021 owns pids/sockets lifecycle.
    PRESERVED_BASENAMES = %w[restart.txt secret_token puma.state].freeze
    PRESERVED_SUBDIRS = %w[pids sockets].freeze

    module_function

    def tmp_root
      Rails.root.join('tmp')
    end

    def file_store?
      Rails.cache.is_a?(ActiveSupport::Cache::FileStore)
    end

    def redis_cache_store?
      Rails.cache.is_a?(ActiveSupport::Cache::RedisCacheStore)
    end

    def cache_backend_name
      return 'file_store' if file_store?
      return 'redis_cache_store' if redis_cache_store?

      Rails.cache.class.name
    end

    # Startup / crash recovery: age-bounded orphans + expired FileStore entries.
    # Safe during web boot; skipped in test unless forced.
    def startup_cleanup!(orphan_max_age: DEFAULT_ORPHAN_MAX_AGE, force: false)
      return skip_report('test_environment') if Rails.env.test? && !force
      return skip_report('disabled') if disabled?

      run_cleanup!(orphan_max_age: orphan_max_age, prune_stale_file_cache: true, source: 'startup')
    end

    # Periodic / rake entry point.
    def periodic_cleanup!(orphan_max_age: DEFAULT_ORPHAN_MAX_AGE)
      return skip_report('disabled') if disabled?

      run_cleanup!(orphan_max_age: orphan_max_age, prune_stale_file_cache: true, source: 'periodic')
    end

    def run_cleanup!(orphan_max_age:, prune_stale_file_cache:, source:)
      report = {
        source: source,
        cache_backend: cache_backend_name,
        orphan_removed: 0,
        orphan_preserved: 0,
        orphan_skipped: 0,
        file_store_expired_cleanup: false,
        file_store_hard_pruned: 0,
        redis_keys_touched: 0,
        errors: [],
      }

      begin
        orphan_stats = cleanup_orphaned_tempfiles!(max_age: orphan_max_age)
        report.merge!(orphan_stats.slice(:orphan_removed, :orphan_preserved, :orphan_skipped))
      rescue StandardError => e
        report[:errors] << "orphans: #{e.class}: #{e.message}"
        logger.warn("F020_TMP_CLEANUP_ORPHAN_ERROR: #{e.class}: #{e.message}")
      end

      begin
        cache_stats = cleanup_file_store_cache!(prune_stale: prune_stale_file_cache)
        report[:file_store_expired_cleanup] = cache_stats[:expired_cleanup]
        report[:file_store_hard_pruned] = cache_stats[:hard_pruned]
        report[:cache_note] = cache_stats[:note]
      rescue StandardError => e
        report[:errors] << "cache: #{e.class}: #{e.message}"
        logger.warn("F020_TMP_CLEANUP_CACHE_ERROR: #{e.class}: #{e.message}")
      end

      logger.info(
        "F020_TMP_CLEANUP source=#{report[:source]} backend=#{report[:cache_backend]} " \
        "orphans_removed=#{report[:orphan_removed]} orphans_preserved=#{report[:orphan_preserved]} " \
        "file_store_expired=#{report[:file_store_expired_cleanup]} " \
        "file_store_hard_pruned=#{report[:file_store_hard_pruned]} " \
        "errors=#{report[:errors].size}"
      )
      report
    end

    # Remove regular files directly under tmp/ that look like abandoned Tempfile
    # artifacts and are older than max_age. Never descends into preserved subdirs.
    def cleanup_orphaned_tempfiles!(max_age: DEFAULT_ORPHAN_MAX_AGE, root: nil)
      root_path = resolve_cleanup_root(root || tmp_root)
      cutoff = Time.now.utc - max_age
      removed = 0
      preserved = 0
      skipped = 0

      Dir.children(root_path).each do |name|
        if PRESERVED_BASENAMES.include?(name) || PRESERVED_SUBDIRS.include?(name)
          preserved += 1
          next
        end

        # FileStore directory is cleaned separately; do not age-delete active cache tree here.
        if name == 'cache'
          preserved += 1
          next
        end

        candidate = File.join(root_path, name)
        unless File.lstat(candidate).file?
          skipped += 1
          next
        end

        # Refuse symlink entries (even if dangling) — no unlink of link nodes that
        # could have been swapped; only plain files we own under root.
        if File.symlink?(candidate)
          skipped += 1
          next
        end

        real = safe_realpath(candidate, root_path)
        unless real
          skipped += 1
          next
        end

        mtime = File.mtime(real).utc
        if mtime > cutoff
          preserved += 1
          next
        end

        File.unlink(real)
        removed += 1
      rescue Errno::ENOENT
        skipped += 1
      rescue StandardError => e
        skipped += 1
        logger.debug("F020_TMP_ORPHAN_SKIP path=#{name} err=#{e.class}: #{e.message}")
      end

      { orphan_removed: removed, orphan_preserved: preserved, orphan_skipped: skipped, root: root_path }
    end

    def cleanup_file_store_cache!(prune_stale: true, hard_max_age: DEFAULT_FILE_CACHE_HARD_MAX_AGE)
      unless file_store?
        return {
          expired_cleanup: false,
          hard_pruned: 0,
          note: "skipped_non_file_store:#{cache_backend_name}",
        }
      end

      Rails.cache.cleanup
      hard_pruned = 0
      hard_pruned = prune_stale_file_cache_files!(max_age: hard_max_age) if prune_stale

      {
        expired_cleanup: true,
        hard_pruned: hard_pruned,
        note: 'file_store_cleanup_ok',
      }
    end

    # Age-bound hard prune for FileStore files that never received expires_in
    # (or survived process crashes). Only under the configured FileStore cache path.
    def prune_stale_file_cache_files!(max_age: DEFAULT_FILE_CACHE_HARD_MAX_AGE)
      cache_path = file_store_cache_path
      return 0 unless cache_path

      root = resolve_cleanup_root(cache_path)
      cutoff = Time.now.utc - max_age
      removed = 0

      Find.find(root) do |path|
        next unless File.file?(path)
        next if File.symlink?(path)

        real = safe_realpath(path, root)
        next unless real
        next if File.mtime(real).utc > cutoff

        File.unlink(real)
        removed += 1
      rescue Errno::ENOENT
        next
      end

      removed
    end

    def file_store_cache_path
      return unless file_store?

      Rails.cache.cache_path
    rescue StandardError
      Rails.root.join('tmp', 'cache').to_s
    end

    def resolve_cleanup_root(path)
      expanded = File.expand_path(path.to_s)
      raise ArgumentError, "cleanup root missing: #{expanded}" unless File.directory?(expanded)

      real = File.realpath(expanded)
      tmp_real = File.realpath(File.expand_path(tmp_root.to_s))
      unless real == tmp_real || real.start_with?(tmp_real + File::SEPARATOR)
        raise ArgumentError, "cleanup root escapes tmp: #{real}"
      end

      real
    end

    # Returns realpath string only if it stays under root_real; nil otherwise.
    def safe_realpath(path, root_real)
      return nil if File.symlink?(path)

      real = File.realpath(path)
      return real if real == root_real || real.start_with?(root_real + File::SEPARATOR)

      nil
    rescue Errno::ENOENT
      nil
    end

    def disabled?
      Foreman::Cast.to_bool(ENV['FOREMAN_SKIP_TMP_CACHE_CLEANUP'])
    end

    def skip_report(reason)
      {
        source: 'skipped',
        cache_backend: (cache_backend_name rescue 'unknown'),
        orphan_removed: 0,
        orphan_preserved: 0,
        orphan_skipped: 0,
        file_store_expired_cleanup: false,
        file_store_hard_pruned: 0,
        redis_keys_touched: 0,
        errors: [],
        note: reason,
      }
    end

    def logger
      Foreman::Logging.logger('app')
    rescue StandardError
      Rails.logger
    end
  end
end
