# frozen_string_literal: true

class CreateUserLoginEvents < ActiveRecord::Migration[7.0]
  def up
    return if table_exists?(:user_login_events)

    create_table :user_login_events do |t|
      t.references :user, null: false, foreign_key: { on_delete: :cascade }, index: true
      t.datetime :logged_in_at, null: false
      t.string :remote_ip, limit: 255
      t.string :request_host, limit: 255
      t.string :auth_method, limit: 64
      t.string :auth_source_name, limit: 255
    end

    add_index :user_login_events, [:user_id, :logged_in_at],
              name: 'index_user_login_events_on_user_id_and_logged_in_at'
  end

  def down
    drop_table :user_login_events if table_exists?(:user_login_events)
  end
end
