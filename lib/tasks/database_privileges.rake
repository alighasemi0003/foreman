# frozen_string_literal: true

namespace :security do
  desc 'F-014: report PostgreSQL role privilege posture (advisory; does not revoke)'
  task check_database_privileges: :environment do
    require 'json'
    require 'foreman/database_privilege_inventory'
    report = Foreman::DatabasePrivilegeInventory.report
    puts JSON.pretty_generate(report)
    if report[:ok]
      puts 'database privilege inventory: least-privilege attributes look clear'
    else
      warn 'database privilege inventory: elevated attributes present — see docs/security/database-privilege-inventory.md'
      # Advisory: do not abort lab Compose (SUPERUSER by design). Exit 0 unless
      # FOREMAN_DB_PRIVILEGE_ENFORCE=1 is set for production gates.
      abort('elevated database role attributes') if ENV['FOREMAN_DB_PRIVILEGE_ENFORCE'] == '1'
    end
  end
end
