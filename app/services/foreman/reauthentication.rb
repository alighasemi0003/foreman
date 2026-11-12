# frozen_string_literal: true

module Foreman
  # Step-up authentication for sensitive interactive-session actions.
  # Recent-auth state lives in the Rails session (session-bound + actor-bound).
  # Never call User.try_to_login from this module.
  #
  # F-011: administrators may toggle only *registered configurable* operations via
  # Administer → Settings → "Re-authentication policy". Arbitrary controller/URL
  # registration is rejected. Mandatory operations cannot be disabled.
  module Reauthentication
    SESSION_AT = :reauthenticated_at
    SESSION_ACTOR = :reauth_actor_id

    Operation = Struct.new(
      :key, :label, :description, :setting_name, :mandatory, :default_enabled,
      keyword_init: true
    )

    META_ACTION_KEY = 'settings.reauthentication.update'
    OAUTH_CREDENTIALS_ACTION_KEY = 'settings.oauth_credentials.update'

    # Closed server-side registry. Unknown keys are never introduced by Settings.
    OPERATIONS = [
      Operation.new(
        key: META_ACTION_KEY,
        label: N_('Update re-authentication policy'),
        description: N_('Changing the re-authentication window or any require_reauth_* toggle. Always required; cannot be disabled.'),
        setting_name: 'require_reauth_settings_reauthentication_policy',
        mandatory: true,
        default_enabled: true
      ),
      Operation.new(
        key: OAUTH_CREDENTIALS_ACTION_KEY,
        label: N_('Update OAuth API credentials'),
        description: N_('Changing oauth_consumer_key or oauth_consumer_secret. Always required; cannot be disabled.'),
        setting_name: 'require_reauth_settings_oauth_credentials',
        mandatory: true,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.set_admin',
        label: N_('Change user administrator flag'),
        description: N_('Granting or revoking the administrator flag on a user.'),
        setting_name: 'require_reauth_users_set_admin',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.set_disabled',
        label: N_('Enable or disable a user'),
        description: N_('Enabling or disabling a user account.'),
        setting_name: 'require_reauth_users_set_disabled',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.impersonate',
        label: N_('Impersonate a user'),
        description: N_('Impersonating another user.'),
        setting_name: 'require_reauth_users_impersonate',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'auth_sources.update',
        label: N_('Update authentication source'),
        description: N_('Updating an authentication source (for example LDAP).'),
        setting_name: 'require_reauth_auth_sources_update',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.destroy',
        label: N_('Delete a user'),
        description: N_('Deleting a user account.'),
        setting_name: 'require_reauth_users_destroy',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.change_password',
        label: N_('Change another user password'),
        description: N_('Changing another user\'s password (administrator reset).'),
        setting_name: 'require_reauth_users_change_password',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.change_roles',
        label: N_('Change user roles'),
        description: N_('Changing user role membership or role/filter definitions.'),
        setting_name: 'require_reauth_users_change_roles',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'auth_sources.create',
        label: N_('Create authentication source'),
        description: N_('Creating an authentication source.'),
        setting_name: 'require_reauth_auth_sources_create',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'auth_sources.destroy',
        label: N_('Delete authentication source'),
        description: N_('Deleting an authentication source.'),
        setting_name: 'require_reauth_auth_sources_destroy',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.terminate_sessions',
        label: N_('Terminate user sessions'),
        description: N_('Terminating interactive user sessions.'),
        setting_name: 'require_reauth_users_terminate_sessions',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.invalidate_jwt',
        label: N_('Invalidate registration JWTs'),
        description: N_('Invalidating user registration JWTs.'),
        setting_name: 'require_reauth_users_invalidate_jwt',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'users.create',
        label: N_('Create a user'),
        description: N_('Creating a user account.'),
        setting_name: 'require_reauth_users_create',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'personal_access_tokens.create',
        label: N_('Create personal access token'),
        description: N_('Creating a personal access token.'),
        setting_name: 'require_reauth_personal_access_tokens_create',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'personal_access_tokens.revoke',
        label: N_('Revoke personal access token'),
        description: N_('Revoking a personal access token.'),
        setting_name: 'require_reauth_personal_access_tokens_revoke',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'ssh_keys.create',
        label: N_('Create SSH key'),
        description: N_('Adding an SSH public key to a user.'),
        setting_name: 'require_reauth_ssh_keys_create',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'ssh_keys.destroy',
        label: N_('Delete SSH key'),
        description: N_('Deleting a user SSH public key.'),
        setting_name: 'require_reauth_ssh_keys_destroy',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'registration_commands.create',
        label: N_('Generate registration command'),
        description: N_('Generating a host registration command (issues a registration JWT).'),
        setting_name: 'require_reauth_registration_commands_create',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'key_pairs.download',
        label: N_('Download compute SSH private key'),
        description: N_('Downloading a compute resource SSH private key (PEM).'),
        setting_name: 'require_reauth_key_pairs_download',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'key_pairs.recreate',
        label: N_('Recreate compute SSH key pair'),
        description: N_('Recreating a compute resource SSH key pair.'),
        setting_name: 'require_reauth_key_pairs_recreate',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'key_pairs.destroy',
        label: N_('Delete compute SSH key'),
        description: N_('Deleting a compute resource SSH key.'),
        setting_name: 'require_reauth_key_pairs_destroy',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'hosts.console',
        label: N_('Open host console'),
        description: N_('Opening a host console (VNC/SPICE may embed a short-lived display password).'),
        setting_name: 'require_reauth_hosts_console',
        mandatory: false,
        default_enabled: true
      ),
      Operation.new(
        key: 'compute_resources_vms.console',
        label: N_('Open compute resource VM console'),
        description: N_('Opening a compute resource VM console.'),
        setting_name: 'require_reauth_compute_resources_vms_console',
        mandatory: false,
        default_enabled: true
      ),
    ].freeze

    OPERATIONS_BY_KEY = OPERATIONS.index_by(&:key).freeze

    # Canonical action key => Setting name for *configurable* (non-mandatory) ops.
    ACTION_SETTINGS = OPERATIONS.reject(&:mandatory).to_h { |op| [op.key, op.setting_name] }.freeze

    # Settings that always require reauth (no toggle) — OAuth API credentials.
    ALWAYS_REAUTH_SETTING_NAMES = %w[
      oauth_consumer_key
      oauth_consumer_secret
    ].freeze

    ALWAYS_ON_ACTION_KEYS = OPERATIONS.select(&:mandatory).map(&:key).freeze

    MANDATORY_SETTING_NAMES = OPERATIONS.select(&:mandatory).map(&:setting_name).freeze

    META_SETTING_NAMES = (
      ['reauthentication_window_minutes'] + OPERATIONS.map(&:setting_name)
    ).freeze

    SETTINGS_CATEGORY = 'reauthentication'

    module_function

    def operations
      OPERATIONS
    end

    def operation(key)
      OPERATIONS_BY_KEY[key.to_s]
    end

    def registered_operation?(key)
      OPERATIONS_BY_KEY.key?(key.to_s)
    end

    def mandatory_operation?(key)
      op = operation(key)
      op&.mandatory || false
    end

    def mandatory_setting?(name)
      MANDATORY_SETTING_NAMES.include?(name.to_s)
    end

    # Effective policy for UI/API inventory: :mandatory_enabled, :enabled, :disabled
    def effective_policy(action_key)
      return :unknown unless registered_operation?(action_key)
      return :mandatory_enabled if mandatory_operation?(action_key)

      policy_enabled?(action_key) ? :enabled : :disabled
    end

    def policy_inventory
      OPERATIONS.map do |op|
        {
          key: op.key,
          label: _(op.label),
          description: _(op.description),
          setting_name: op.setting_name,
          mandatory: op.mandatory,
          default_enabled: op.default_enabled,
          effective: effective_policy(op.key),
          enabled: policy_enabled?(op.key),
        }
      end
    end

    def real_actor_id(session)
      (session[:impersonated_by].presence || session[:user]).presence&.to_i
    end

    def real_actor(session)
      id = real_actor_id(session)
      return nil if id.blank?

      User.unscoped.find_by(id: id)
    end

    def interactive_session?(session)
      session[:user].present? && !session[:api_authenticated_session]
    end

    # Fail-secure: only explicit false disables a *configurable* action policy.
    # Mandatory and unknown registered-missing keys remain enabled.
    def policy_enabled?(action_key)
      key = action_key.to_s
      return true if ALWAYS_ON_ACTION_KEYS.include?(key)

      op = operation(key)
      return true if op.nil? # unknown guard key → require reauth (fail closed)
      return true if op.mandatory

      Setting[op.setting_name] != false
    rescue StandardError
      true
    end

    def required_for?(action_key, session:)
      return false unless interactive_session?(session)
      return false unless policy_enabled?(action_key)

      !recently_authenticated?(session)
    end

    def recently_authenticated?(session)
      actor_id = real_actor_id(session)
      return false if actor_id.blank?

      stored_actor = session[SESSION_ACTOR].presence&.to_i
      return false if stored_actor.blank? || stored_actor != actor_id

      at = session[SESSION_AT].presence&.to_i
      return false if at.blank? || at <= 0

      window = window_minutes
      (Time.now.utc.to_i - at) < (window * 60)
    end

    def window_minutes
      value = Setting[:reauthentication_window_minutes].to_i
      return 5 unless value.between?(1, 30)

      value
    rescue StandardError
      5
    end

    def mark_authenticated!(session, actor)
      return unless actor

      session[SESSION_AT] = Time.now.utc.to_i
      session[SESSION_ACTOR] = actor.id
    end

    def clear!(session)
      session.delete(SESSION_AT)
      session.delete(SESSION_ACTOR)
    end

    def marks_login_as_fresh?(user)
      return false unless user
      return true if user.internal?
      return true if user.auth_source.is_a?(AuthSourceLdap)

      false
    end

    # Whether the actor can complete step-up with a password (Local/LDAP).
    def supported_for?(actor)
      return false unless actor
      return true if actor.internal?
      return true if actor.auth_source.is_a?(AuthSourceLdap)

      false
    end

    def meta_setting?(name)
      META_SETTING_NAMES.include?(name.to_s)
    end

    def always_reauth_setting?(name)
      ALWAYS_REAUTH_SETTING_NAMES.include?(name.to_s)
    end

    # Action key for a setting name that requires step-up, or nil if not gated.
    def action_key_for_setting(name)
      return META_ACTION_KEY if meta_setting?(name)
      return OAUTH_CREDENTIALS_ACTION_KEY if always_reauth_setting?(name)

      nil
    end

    def admin_transition?(user, params)
      return false unless user
      return false unless params.key?(:admin) || params.key?('admin')

      new_val = ActiveModel::Type::Boolean.new.cast(params[:admin].nil? ? params['admin'] : params[:admin])
      new_val != !!user.admin?
    end

    def disabled_transition?(user, params)
      return false unless user
      return false unless params.key?(:disabled) || params.key?('disabled')

      new_val = ActiveModel::Type::Boolean.new.cast(params[:disabled].nil? ? params['disabled'] : params[:disabled])
      new_val != !!user.disabled?
    end

    # Other-user password mutation only (self uses existing current_password flow).
    def password_change_other_transition?(user, params)
      return false unless user
      return false if User.current && user.id == User.current.id
      return false unless params.key?(:password) || params.key?('password')

      password = params[:password].nil? ? params['password'] : params[:password]
      password.present?
    end

    def roles_transition?(user, params)
      return false unless user

      new_ids = extract_role_ids(params)
      return false if new_ids.nil?

      new_ids.sort != user.role_ids.sort
    end

    # Returns action keys that apply to a users update payload (may be empty / multiple).
    # One fresh authentication satisfies all keys in the same request.
    def user_update_action_keys(user, params)
      keys = []
      keys << 'users.set_admin' if admin_transition?(user, params)
      keys << 'users.set_disabled' if disabled_transition?(user, params)
      keys << 'users.change_password' if password_change_other_transition?(user, params)
      keys << 'users.change_roles' if roles_transition?(user, params)
      keys
    end

    def extract_role_ids(params)
      if params.key?(:role_ids) || params.key?('role_ids')
        Array(params[:role_ids] || params['role_ids']).map(&:to_i).reject(&:zero?)
      elsif params.key?(:role_names) || params.key?('role_names')
        names = Array(params[:role_names] || params['role_names']).map(&:to_s)
        Role.where(:name => names).pluck(:id)
      elsif params.key?(:roles) || params.key?('roles')
        raw = Array(params[:roles] || params['roles'])
        raw.map { |r| r.to_s.match?(/\A\d+\z/) ? r.to_i : Role.find_by(:name => r.to_s)&.id }.compact
      end
    end
  end
end
