#!/usr/bin/env ruby
# frozen_string_literal: true

# F-021: container pre-start cleanup of stale PID/state/sockets.
# Stdlib + Foreman::RuntimeStateLifecycle only (no Rails/DB).
#
# Usage:
#   safe_clean_runtime_state.rb [APP_ROOT]
# Env:
#   FOREMAN_SKIP_RUNTIME_STATE_CLEANUP=1  — no-op exit 0
#   FOREMAN_APP_ROOT                      — default app root

root = File.expand_path(ARGV[0] || ENV.fetch('FOREMAN_APP_ROOT', '/home/foreman'))
if %w[1 true yes on].include?(ENV['FOREMAN_SKIP_RUNTIME_STATE_CLEANUP'].to_s.downcase)
  warn 'F021_RUNTIME_CLEANUP skipped=env'
  exit 0
end

home_lib = File.join(root, 'lib')
$LOAD_PATH.unshift(home_lib) if File.directory?(home_lib)

# When executed from the repo tree (not /usr/bin), also allow relative lib/.
repo_lib = File.expand_path('../../lib', __dir__)
$LOAD_PATH.unshift(repo_lib) if File.directory?(repo_lib) && !$LOAD_PATH.include?(repo_lib)

begin
  require 'foreman/runtime_state_lifecycle'
rescue LoadError => e
  warn "F021_RUNTIME_CLEANUP load_error=#{e.message}"
  exit 0
end

tmp = File.join(root, 'tmp')
unless File.directory?(tmp)
  warn "F021_RUNTIME_CLEANUP skip missing_tmp=#{tmp}"
  exit 0
end

report = Foreman::RuntimeStateLifecycle.prestart_cleanup!(root: tmp)
warn "F021_RUNTIME_CLEANUP done=#{report.inspect}"
exit 0
