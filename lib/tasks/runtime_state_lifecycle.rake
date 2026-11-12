# frozen_string_literal: true

namespace :tmp do
  desc 'F-021: safely clean stale PID/state/sockets and aged test reporter files'
  task runtime_state: :environment do
    require 'foreman/runtime_state_lifecycle'
    report = Foreman::RuntimeStateLifecycle.runtime_maintenance!(root: Rails.root.join('tmp'))
    puts "F021_RUNTIME_CLEANUP #{report.inspect}"
  end
end
