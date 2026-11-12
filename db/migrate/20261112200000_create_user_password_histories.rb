# frozen_string_literal: true

class CreateUserPasswordHistories < ActiveRecord::Migration[7.0]
  def up
    return if table_exists?(:user_password_histories)

    create_table :user_password_histories do |t|
      t.references :user, null: false, foreign_key: { on_delete: :cascade }, index: false
      # Same verification material as users.password_hash / password_salt — never plaintext.
      t.string :password_hash, null: false
      t.string :password_salt, null: false
      t.datetime :created_at, null: false
    end

    add_index :user_password_histories, [:user_id, :created_at],
              name: 'index_user_password_histories_on_user_id_and_created_at'
  end

  def down
    drop_table :user_password_histories if table_exists?(:user_password_histories)
  end
end
