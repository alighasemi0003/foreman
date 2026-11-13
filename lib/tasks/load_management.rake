# frozen_string_literal: true

namespace :security do
  desc 'F-029: report load-management posture (advisory; no scheduler)'
  task check_load_management_posture: :environment do
    require 'json'
    require 'foreman/load_management_posture'
    puts JSON.pretty_generate(Foreman::LoadManagementPosture.report)
  end
end
