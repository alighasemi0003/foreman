class AddAccountLockoutFieldsToUsers < ActiveRecord::Migration[7.0]
  def up
    add_column :users, :failed_login_attempts, :integer, :default => 0, :null => false unless column_exists?(:users, :failed_login_attempts)
    add_column :users, :failed_login_started_at, :datetime unless column_exists?(:users, :failed_login_started_at)
    add_column :users, :locked_until, :datetime unless column_exists?(:users, :locked_until)
  end

  def down
    remove_column :users, :failed_login_attempts if column_exists?(:users, :failed_login_attempts)
    remove_column :users, :failed_login_started_at if column_exists?(:users, :failed_login_started_at)
    remove_column :users, :locked_until if column_exists?(:users, :locked_until)
  end
end
