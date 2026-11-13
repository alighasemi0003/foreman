# frozen_string_literal: true

require 'test_helper'
require 'foreman/dead_code_analysis'
require 'tmpdir'

class DeadCodeAnalysisTest < ActiveSupport::TestCase
  test 'report is analysis-only and never lists auto deletions' do
    Dir.mktmpdir do |dir|
      todo = File.join(dir, '.rubocop_todo.yml')
      File.write(todo, <<~YAML)
        Lint/UnusedBlockArgument:
          Enabled: false
        Lint/UnusedMethodArgument:
          Enabled: false
      YAML
      routes = [
        { controller: 'hosts', action: 'index' },
        { controller: 'hosts', action: 'show' }
      ]
      report = Foreman::DeadCodeAnalysis.new(routes: routes, rubocop_todo_path: todo).report
      assert_equal 'F-036', report[:task]
      assert_equal 'ANALYSIS_ONLY', report[:status]
      assert_equal false, report[:production_code_removed_this_task]
      assert_equal 0, report[:confirmed_unused_count]
      assert_equal false, report[:rubocop_unused_cops]['Lint/UnusedMethodArgument'][:enabled]
      assert_equal 2, report[:routes][:routed_controller_actions]
    end
  end
end
