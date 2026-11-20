# frozen_string_literal: true

namespace :security do
  desc <<~DESC
    Show or apply the Foreman 5.0 secure-defaults baseline to Settings.
      rake security:secure_defaults              # dry-run (default)
      rake security:secure_defaults APPLY=1      # persist changes
      rake security:secure_defaults APPLY=1 FORCE=1  # overwrite customized values too
  DESC
  task secure_defaults: :environment do
    apply = %w[1 true yes].include?(ENV.fetch('APPLY', '0').to_s.downcase)
    force = %w[1 true yes].include?(ENV.fetch('FORCE', '0').to_s.downcase)

    result = if apply
               Foreman::SecureDefaults.apply!(force: force, set_baseline: true, dry_run: false)
             else
               plan = Foreman::SecureDefaults.plan(force: force)
               {
                 status: :dry_run,
                 baseline: Foreman::SecureDefaults.baseline_id,
                 applied: plan.select { |c| c.action == :update },
                 skipped: plan.reject { |c| c.action == :update },
               }
             end

    Foreman::SecureDefaults.report_lines(result).each { |line| puts line }
    puts "effective captcha_enabled=#{Setting[:captcha_enabled]}"
    puts "effective password_max_age=#{Setting[:password_max_age]}"
    puts "effective idle_timeout=#{Setting[:idle_timeout]}"
    puts "effective http_rate_limit_fail_closed=#{Setting[:http_rate_limit_fail_closed]}"
    puts "effective output_classification_enabled=#{Setting[:output_classification_enabled]}"
    puts "baseline_marker=#{Setting[:security_hardening_baseline]}"
  end
end
