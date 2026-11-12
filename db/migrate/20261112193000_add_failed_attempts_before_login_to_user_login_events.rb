# frozen_string_literal: true

class AddFailedAttemptsBeforeLoginToUserLoginEvents < ActiveRecord::Migration[7.0]
  def up
    return unless table_exists?(:user_login_events)
    return if column_exists?(:user_login_events, :failed_attempts_before_login)

    add_column :user_login_events, :failed_attempts_before_login, :integer, null: false, default: 0
  end

  def down
    return unless table_exists?(:user_login_events)
    return unless column_exists?(:user_login_events, :failed_attempts_before_login)

    remove_column :user_login_events, :failed_attempts_before_login
  end
end
