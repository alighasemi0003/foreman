# frozen_string_literal: true

class AddPasswordChangeRequiredToUsers < ActiveRecord::Migration[7.0]
  def up
    # Prefer password_change_required (may already exist on long-lived DBs).
    if column_exists?(:users, :force_password_change) && !column_exists?(:users, :password_change_required)
      rename_column :users, :force_password_change, :password_change_required
    elsif !column_exists?(:users, :password_change_required)
      add_column :users, :password_change_required, :boolean, :default => false, :null => false
    end
  end

  def down
    # Leave the column in place — removing it would risk wiping an existing
    # operational flag on shared databases. No-op by design.
  end
end
