# frozen_string_literal: true

require 'test_helper'
require 'foreman/load_management_posture'

class LoadManagementPostureTest < ActiveSupport::TestCase
  test 'report marks policy required and rejects speculative scheduler' do
    report = Foreman::LoadManagementPosture.report
    assert_equal 'F-029', report[:task]
    assert_equal 'POLICY_REQUIRED', report[:status]
    assert_equal false, report[:speculative_scheduler]
    assert_equal 'not_honored', report[:client_priority_headers]
    assert report[:controls][:output_classification_is_not_slo]
  end
end
