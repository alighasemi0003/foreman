# frozen_string_literal: true

namespace :security do
  desc 'F-036: non-destructive dead-code analysis report (never deletes code)'
  task dead_code_report: :environment do
    require 'json'
    require 'foreman/dead_code_analysis'

    # Eager-load app code so ObjectSpace controller scan is meaningful.
    begin
      Rails.application.eager_load!
    rescue StandardError => e
      warn "eager_load skipped: #{e.class}"
    end

    report = Foreman::DeadCodeAnalysis.report
    # Truncate candidate list in stdout for readability; full count retained.
    printable = report.merge(
      controller_action_candidates: report[:controller_action_candidates].first(50),
      controller_action_candidates_truncated: report[:controller_action_candidate_count] > 50
    )
    puts JSON.pretty_generate(printable)

    if ENV['FOREMAN_DEAD_CODE_ENFORCE'] == '1' && !report[:confirmed_unused].empty?
      warn 'confirmed_unused entries present — review for manual removal PRs'
    end
    # Always succeed: analysis is advisory. Silent auto-deletion is forbidden.
  end
end
