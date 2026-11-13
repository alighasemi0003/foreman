# frozen_string_literal: true

module Foreman
  # F-029: advisory snapshot of capacity / queue posture.
  # Does not schedule requests or assign priority from classification labels.
  class LoadManagementPosture
    def self.report
      new.report
    end

    def report
      {
        task: 'F-029',
        status: 'POLICY_REQUIRED',
        note: 'Data classification (F-013) is not an availability priority. ' \
              'See docs/load-management-policy.md',
        controls: {
          http_rate_limit: setting_bool('http_rate_limit_enabled'),
          connection_capacity_doc: 'docs/connection-capacity.md',
          request_body_limits_doc: 'docs/http-request-body-limits.md',
          output_classification_is_not_slo: true
        },
        runtime: runtime_snapshot,
        speculative_scheduler: false,
        client_priority_headers: 'not_honored'
      }
    end

    private

    def setting_bool(name)
      return nil unless defined?(Setting)
      ActiveModel::Type::Boolean.new.cast(Setting[name])
    rescue StandardError
      nil
    end

    def runtime_snapshot
      {
        puma_workers: ENV['FOREMAN_PUMA_WORKERS'],
        puma_threads_max: ENV['FOREMAN_PUMA_THREADS_MAX'] || ENV['RAILS_MAX_THREADS'],
        sidekiq_concurrency: ENV['FOREMAN_SIDEKIQ_CONCURRENCY'],
        database_pool: database_pool,
        active_job_adapter: (Rails.application.config.active_job.queue_adapter rescue nil).to_s
      }
    end

    def database_pool
      ActiveRecord::Base.connection_pool.size
    rescue StandardError
      nil
    end
  end
end
