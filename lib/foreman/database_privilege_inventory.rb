# frozen_string_literal: true

module Foreman
  # F-014: advisory inventory of the current PostgreSQL role and app routines.
  # Does not revoke privileges or modify schema.
  class DatabasePrivilegeInventory
    Result = Struct.new(
      :ok, :adapter, :database, :role, :superuser, :createrole, :createdb,
      :replication, :bypassrls, :user_routines, :user_triggers, :findings,
      :task, keyword_init: true
    )

    def self.report(connection: ActiveRecord::Base.connection)
      new(connection).report
    end

    def initialize(connection)
      @connection = connection
    end

    def report
      unless postgresql?
        return Result.new(
          ok: true,
          adapter: @connection.adapter_name,
          database: nil,
          role: nil,
          superuser: nil,
          createrole: nil,
          createdb: nil,
          replication: nil,
          bypassrls: nil,
          user_routines: 0,
          user_triggers: 0,
          findings: ['non-PostgreSQL adapter — inventory skipped'],
          task: 'F-014'
        ).to_h
      end

      attrs = role_attributes
      routines = user_routine_count
      triggers = user_trigger_count
      findings = []
      findings << 'runtime role has SUPERUSER — use a least-privilege app role in production' if attrs[:superuser]
      findings << 'runtime role has CREATEROLE' if attrs[:createrole]
      findings << 'runtime role has CREATEDB' if attrs[:createdb]
      findings << 'runtime role has REPLICATION' if attrs[:replication]
      findings << 'runtime role has BYPASSRLS' if attrs[:bypassrls]

      # Lab Compose uses SUPERUSER by design; ok=false signals production gap.
      Result.new(
        ok: findings.empty?,
        adapter: @connection.adapter_name,
        database: select_value('SELECT current_database()'),
        role: select_value('SELECT current_user'),
        superuser: attrs[:superuser],
        createrole: attrs[:createrole],
        createdb: attrs[:createdb],
        replication: attrs[:replication],
        bypassrls: attrs[:bypassrls],
        user_routines: routines,
        user_triggers: triggers,
        findings: findings,
        task: 'F-014'
      ).to_h
    end

    private

    def postgresql?
      @connection.adapter_name == 'PostgreSQL'
    end

    def select_value(sql)
      @connection.select_value(sql)
    end

    def role_attributes
      row = @connection.select_one(<<~SQL.squish)
        SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
        FROM pg_roles WHERE rolname = current_user
      SQL
      {
        superuser: row['rolsuper'] == true || row['rolsuper'] == 't',
        createrole: row['rolcreaterole'] == true || row['rolcreaterole'] == 't',
        createdb: row['rolcreatedb'] == true || row['rolcreatedb'] == 't',
        replication: row['rolreplication'] == true || row['rolreplication'] == 't',
        bypassrls: row['rolbypassrls'] == true || row['rolbypassrls'] == 't'
      }
    end

    def user_routine_count
      select_value(<<~SQL.squish).to_i
        SELECT COUNT(*) FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      SQL
    end

    def user_trigger_count
      select_value(<<~SQL.squish).to_i
        SELECT COUNT(*) FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE NOT t.tgisinternal AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      SQL
    end
  end
end
