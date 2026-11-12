# frozen_string_literal: true

# Default Puma config for `bin/rails server`. Packaged Foreman installs typically
# start with `puma -C config/puma/production.rb`; keep both entry points aligned.
env = ENV.fetch('RAILS_ENV', 'development')
env_file = File.expand_path("puma/#{env}.rb", __dir__)

if File.exist?(env_file)
  instance_eval(File.read(env_file), env_file)
else
  # Minimal development defaults — still enforce an absolute body ceiling (F-028).
  threads ENV.fetch('FOREMAN_PUMA_THREADS_MIN', 0).to_i,
          ENV.fetch('FOREMAN_PUMA_THREADS_MAX') { ENV.fetch('RAILS_MAX_THREADS', '5') }.to_i
  http_content_length_limit ENV.fetch(
    'FOREMAN_ABSOLUTE_MAX_REQUEST_BODY_BYTES',
    (10 * 1024 * 1024).to_s
  ).to_i
  port ENV.fetch('PORT', 3000)
end
