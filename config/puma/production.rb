run_dir = Rails.root.join('tmp')
require 'fileutils'
require 'foreman/runtime_state_lifecycle'

# F-021: restrictive runtime dirs for PID / control socket / state.
Foreman::RuntimeStateLifecycle.ensure_runtime_directories!(run_dir)

# Store server info state (mode applied by Puma; re-hardened on_booted).
state_path File.join(run_dir, 'puma.state')
state_permission 0o0640
pidfile File.join(run_dir, 'pids', 'server.pid')

# Configure "min" to be the minimum number of threads to use to answer
# requests and "max" the maximum.
#
# Default max is RAILS_MAX_THREADS (Rails convention) then 16. Keep
# FOREMAN_PUMA_THREADS_MAX / RAILS_MAX_THREADS <= ActiveRecord pool
# (DATABASE_URL ?pool= or database.yml) per worker process — see
# docs/connection-capacity.md (F-027).
#
puma_max_threads = ENV.fetch('FOREMAN_PUMA_THREADS_MAX') { ENV.fetch('RAILS_MAX_THREADS', '16') }.to_i
threads ENV.fetch('FOREMAN_PUMA_THREADS_MIN', 0).to_i, puma_max_threads

# F-028: hard ceiling compared to Content-Length (and body size when CL absent).
# Must be >= largest path exception (facts/reports = 10 MiB). Tighter per-path
# limits are enforced by Foreman::Middleware::RequestBodyLimit (default 2 MiB).
http_content_length_limit ENV.fetch('FOREMAN_ABSOLUTE_MAX_REQUEST_BODY_BYTES', (10 * 1024 * 1024).to_s).to_i

# === Cluster mode ===

# How many worker processes to run.
#
# The default is "0" for puma. Recommending "2" for foreman
# Each worker is a separate process with its own ActiveRecord pool.
#
workers ENV.fetch('FOREMAN_PUMA_WORKERS', 2).to_i

# Puma worker timeout.
#
# It's not recommended to change this, since it can mask real
# bugs or incorrect tuning. This is not a request timeout.
#
worker_timeout ENV.fetch('FOREMAN_PUMA_WORKER_TIMEOUT').to_i if ENV.key?('FOREMAN_PUMA_WORKER_TIMEOUT')

# In clustered mode, Puma can "preload" your application. This loads all the
# application code prior to forking. Preloading reduces total memory usage of
# your application via an operating system feature called copy-on-write
#
preload_app!

# When systemd socket activation is detected, only use those sockets. This
# makes FOREMAN_BIND redundant. The code is still there for non-systemd
# deployments.
bind_to_activated_sockets 'only'

# Check if FOREMAN_BIND was set to an IP address based on the previous
# definition of FOREMAN_BIND. If it is an IP address, define the host
# and port through Puma's DSL. Otherwise rescue and assume the new
# style of a fully specified bind in the formats of:
#
#  * unix:///run/foreman.sock
#  * tcp://127.0.0.1:3000
#
begin
  IPAddr.new(ENV['FOREMAN_BIND'])

  port ENV.fetch('FOREMAN_PORT', '3000'), ENV['FOREMAN_BIND']
rescue IPAddr::Error
  bind ENV.fetch('FOREMAN_BIND', 'tcp://127.0.0.1:3000')
end

on_worker_boot do
  dynflow = ::Rails.application.dynflow
  dynflow.initialize! unless dynflow.config.lazy_initialization
end

# === Puma control rack application ===
# Socket lives under tmp/sockets (0700/0750 dir). Mode tightened in on_booted (F-021).
activate_control_app "unix://#{run_dir}/sockets/pumactl.sock"

on_booted do
  Foreman::RuntimeStateLifecycle.harden_permissions!(run_dir)
end

# Loading and initializing of all gettext languages takes about 100ms per language
# in development environment and little less on production. Let's eager load languages
# for production before forking to save memory on CoW operating systems.
before_fork do
  Foreman::Gettext::Support.human_available_locales
end
