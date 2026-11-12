# frozen_string_literal: true

# F-020: crash-recovery cleanup of orphaned tmp files and expired FileStore
# entries. Skipped in test; disable with FOREMAN_SKIP_TMP_CACHE_CLEANUP=1.
# Does not run destructive Redis FLUSH or wipe of pids/sockets (F-021).
#
# at_exit / SIGKILL are unreliable — startup + daily cron are the recovery path.
Rails.application.config.after_initialize do
  next if Rails.env.test?
  next if Foreman::Cast.to_bool(ENV['FOREMAN_SKIP_TMP_CACHE_CLEANUP'])

  # Avoid interfering with db: / assets: one-shot rake tasks that load the app.
  if defined?(Rake) && Rake.respond_to?(:application) && Rake.application.top_level_tasks.any?
    tasks = Rake.application.top_level_tasks
    next if tasks.any? { |t| t.start_with?('db:', 'assets:', 'webpack:', 'plugin:') }
  end

  begin
    Foreman::TempCacheLifecycle.startup_cleanup!
  rescue StandardError => e
    Rails.logger.warn("F020_TMP_CLEANUP_STARTUP_SKIP: #{e.class}: #{e.message}")
  end
end
