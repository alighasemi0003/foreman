# frozen_string_literal: true

require 'test_helper'
require 'foreman/database_privilege_inventory'

class DatabasePrivilegeInventoryTest < ActiveSupport::TestCase
  test 'report includes F-014 task and routine counts on PostgreSQL' do
    skip 'PostgreSQL required' unless ActiveRecord::Base.connection.adapter_name == 'PostgreSQL'

    report = Foreman::DatabasePrivilegeInventory.report
    assert_equal 'F-014', report[:task]
    assert_equal 'PostgreSQL', report[:adapter]
    assert report.key?(:superuser)
    assert report.key?(:user_routines)
    assert report.key?(:user_triggers)
    assert_kind_of Array, report[:findings]
    assert_kind_of Integer, report[:user_routines]
    assert_kind_of Integer, report[:user_triggers]
  end

  test 'non-PostgreSQL adapter skips with ok true' do
    fake = Object.new
    def fake.adapter_name
      'SQLite3'
    end

    report = Foreman::DatabasePrivilegeInventory.new(fake).report
    assert report[:ok]
    assert_includes report[:findings].join, 'non-PostgreSQL'
  end
end
