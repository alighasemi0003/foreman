# frozen_string_literal: true

class AddPasswordChangedAtToUsers < ActiveRecord::Migration[7.0]
  def up
    return if column_exists?(:users, :password_changed_at)

    add_column :users, :password_changed_at, :datetime, null: true

    # Start the aging clock at migration time for existing internal-password users.
    # This does not invent a historical change date, avoids mass lockout when an
    # administrator later enables password_max_age, and does not leave accounts
    # exempt indefinitely (NULL would otherwise fail closed or be ambiguous).
    say_with_time 'Backfill password_changed_at for AuthSourceInternal users' do
      execute <<~SQL.squish
        UPDATE users
        SET password_changed_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
        WHERE password_changed_at IS NULL
          AND password_hash IS NOT NULL
          AND auth_source_id IN (
            SELECT id FROM auth_sources WHERE type = 'AuthSourceInternal'
          )
      SQL
    end
  end

  def down
    return unless column_exists?(:users, :password_changed_at)

    remove_column :users, :password_changed_at
  end
end
