require 'minitest/reporters'
require 'fileutils'

if ENV['GITHUB_ACTIONS'] == 'true'
  require 'minitest_reporters_github'
  reporters = [MinitestReportersGithub.new]
else
  # F-021: keep test-only reporter state under tmp/test/, not production runtime paths.
  test_tmp = Rails.root.join('tmp', 'test')
  FileUtils.mkdir_p(test_tmp)
  reporters = [
    Minitest::Reporters::JUnitReporter.new('jenkins/reports/unit/'),
    Minitest::Reporters::MeanTimeReporter.new(
      previous_runs_filename: test_tmp.join('foreman_minitest_reporters_previous_run'),
      report_filename: test_tmp.join('foreman_minitest_reporters_report')
    ),
  ]
end

Minitest::Reporters.use! reporters
