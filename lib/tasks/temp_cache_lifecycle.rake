# frozen_string_literal: true

namespace :tmp do
  desc 'F-020: clean orphaned Rails.root/tmp files and expired FileStore cache (safe paths only)'
  task cache_lifecycle: :environment do
    report = Foreman::TempCacheLifecycle.periodic_cleanup!
    puts "F020_TMP_CLEANUP #{report.inspect}"
    raise "tmp:cache_lifecycle reported errors: #{report[:errors]}" if report[:errors]&.any?
  end
end
