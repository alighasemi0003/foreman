# frozen_string_literal: true

require 'yaml'
require 'set'

module Foreman
  # F-036: reproducible, non-destructive dead-code candidate reporting.
  # Does NOT delete methods. Rails dynamic dispatch makes static "unused"
  # findings speculative until manually confirmed.
  class DeadCodeAnalysis
    CATEGORIES = %w[
      confirmed_unused
      probably_unused_review_required
      dynamically_used
      public_extension_api
      deprecated_compatibility
      unknown
    ].freeze

    # Inherited / framework methods that are not route actions but are public.
    NON_ACTION_SUFFIXES = %w[? =].freeze
    # Common Foreman/Rails controller API methods that are not routed actions.
    NON_ACTION_NAMES = %w[
      action_permissions controller_permission model_of_controller
      resource_class resource_name resource_path success_redirect
      resource_scope resource_params find_resource
    ].freeze

    def self.report(routes: nil, rubocop_todo_path: Rails.root.join('.rubocop_todo.yml'))
      new(routes: routes, rubocop_todo_path: rubocop_todo_path).report
    end

    def initialize(routes: nil, rubocop_todo_path:)
      @routes = routes
      @rubocop_todo_path = rubocop_todo_path.to_s
    end

    def report
      {
        task: 'F-036',
        status: 'ANALYSIS_ONLY',
        note: 'No automatic deletion. Lack of textual references ≠ unused in Rails.',
        rubocop_unused_cops: rubocop_unused_cops,
        routes: route_summary,
        controller_action_candidates: controller_candidates.take(200),
        controller_action_candidate_count: controller_candidates.size,
        categories: CATEGORIES,
        confirmed_unused: confirmed_unused_inventory,
        confirmed_unused_count: confirmed_unused_inventory.size,
        production_code_removed_this_task: false,
        process_doc: 'docs/dead-code-analysis.md'
      }
    end

    private

    def rubocop_unused_cops
      todo = if File.file?(@rubocop_todo_path)
               YAML.safe_load(File.read(@rubocop_todo_path), aliases: true)
             else
               {}
             end
      todo = {} unless todo.is_a?(Hash)
      {
        'Lint/UnusedBlockArgument' => cop_status(todo, 'Lint/UnusedBlockArgument'),
        'Lint/UnusedMethodArgument' => cop_status(todo, 'Lint/UnusedMethodArgument')
      }
    end

    def cop_status(todo, name)
      cfg = todo[name]
      return { in_todo: false, enabled: nil } unless cfg.is_a?(Hash)

      {
        in_todo: true,
        enabled: cfg.key?('Enabled') ? cfg['Enabled'] : true,
        exclude_count: Array(cfg['Exclude']).size
      }
    end

    def route_set
      @route_set ||= begin
        list = @routes || Rails.application.routes.routes.map(&:defaults)
        Set.new(
          list.filter_map do |d|
            next if d[:controller].blank? || d[:action].blank?

            "#{d[:controller]}##{d[:action]}"
          end
        )
      end
    end

    def route_summary
      {
        routed_controller_actions: route_set.size,
        note: 'Public controller methods without a matching route are candidates only — ' \
              'many are helpers, inherited APIs, or dynamically invoked.'
      }
    end

    # Controllers that define public instance methods looking like actions but
    # not present in the route set for that controller. Review-required only.
    def controller_candidates
      return @controller_candidates if defined?(@controller_candidates)

      candidates = []
      return @controller_candidates = candidates unless defined?(ApplicationController)

      ObjectSpace.each_object(Class) do |klass|
        next unless klass != ApplicationController
        next unless klass < ApplicationController
        next if klass.name.nil? || klass.name.start_with?('#')

        controller_path = klass.controller_path rescue next
        klass.public_instance_methods(false).each do |meth|
          name = meth.to_s
          next if name.start_with?('_')
          next if NON_ACTION_SUFFIXES.any? { |s| name.end_with?(s) }
          next if NON_ACTION_NAMES.include?(name)
          next if route_set.include?("#{controller_path}##{name}")

          candidates << {
            controller: klass.name,
            controller_path: controller_path,
            method: name,
            visibility: 'public',
            category: 'probably_unused_review_required',
            deletion_risk: 'high',
            disposition: 'review — do not auto-delete'
          }
        end
      rescue StandardError
        next
      end
      @controller_candidates = candidates.sort_by { |c| [c[:controller], c[:method]] }
    end

    # Intentionally empty until a human confirms unused code with runtime evidence.
    # Populate via docs process; never by bulk scanner output alone.
    def confirmed_unused_inventory
      []
    end
  end
end
