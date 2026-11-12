# frozen_string_literal: true

# F-021: post-boot maintenance for runtime PID/state/sockets and test artifacts.
# Pre-start stale cleanup runs from extras/containers/entrypoint.sh (no Rails).
# Skipped in test; disable with FOREMAN_SKIP_RUNTIME_STATE_CLEANUP=1.
Rails.application.config.after_initialize do
  next if Rails.env.test?
  next if Foreman::Cast.to_bool(ENV['FOREMAN_SKIP_RUNTIME_STATE_CLEANUP'])

  if defined?(Rake) && Rake.respond_to?(:application) && Rake.application.top_level_tasks.any?
    tasks = Rake.application.top_level_tasks
    next if tasks.any? { |t| t.start_with?('db:', 'assets:', 'webpack:', 'plugin:') }
  end

  begin
    require 'foreman/runtime_state_lifecycle'
    Foreman::RuntimeStateLifecycle.runtime_maintenance!(root: Rails.root.join('tmp'))
  rescue StandardError => e
    Rails.logger.warn("F021_RUNTIME_CLEANUP_STARTUP_SKIP: #{e.class}: #{e.message}")
  end
end
