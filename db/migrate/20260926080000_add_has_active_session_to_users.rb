# frozen_string_literal: true

class AddHasActiveSessionToUsers < ActiveRecord::Migration[7.0]
  def up
    return if column_exists?(:users, :has_active_session)

    add_column :users, :has_active_session, :boolean, :default => false, :null => false
  end

  def down
    return unless column_exists?(:users, :has_active_session)

    remove_column :users, :has_active_session
  end
end
