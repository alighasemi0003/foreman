# frozen_string_literal: true

module Foreman
  # Step-up authentication for sensitive interactive-session actions.
  # Recent-auth state lives in the Rails session (session-bound + actor-bound).
  # Never call User.try_to_login from this module.
  module Reauthentication
    SESSION_AT = :reauthenticated_at
    SESSION_ACTOR = :reauth_actor_id

    # Canonical action key => Setting name (boolean). Meta policy is hardcoded.
    ACTION_SETTINGS = {
      'users.set_admin' => 'require_reauth_users_set_admin',
      'users.set_disabled' => 'require_reauth_users_set_disabled',
      'users.impersonate' => 'require_reauth_users_impersonate',
      'auth_sources.update' => 'require_reauth_auth_sources_update',
      # Phase 2
      'users.destroy' => 'require_reauth_users_destroy',
      'users.change_password' => 'require_reauth_users_change_password',
      'users.change_roles' => 'require_reauth_users_change_roles',
      'auth_sources.create' => 'require_reauth_auth_sources_create',
      'auth_sources.destroy' => 'require_reauth_auth_sources_destroy',
      'users.terminate_sessions' => 'require_reauth_users_terminate_sessions',
      'users.invalidate_jwt' => 'require_reauth_users_invalidate_jwt',
      # Phase 3A
      'users.create' => 'require_reauth_users_create',
      'personal_access_tokens.create' => 'require_reauth_personal_access_tokens_create',
      'personal_access_tokens.revoke' => 'require_reauth_personal_access_tokens_revoke',
      # Phase 3B
      'ssh_keys.create' => 'require_reauth_ssh_keys_create',
      'ssh_keys.destroy' => 'require_reauth_ssh_keys_destroy',
      'registration_commands.create' => 'require_reauth_registration_commands_create',
      'key_pairs.download' => 'require_reauth_key_pairs_download',
      'key_pairs.recreate' => 'require_reauth_key_pairs_recreate',
      'key_pairs.destroy' => 'require_reauth_key_pairs_destroy',
    }.freeze

    # Settings that always require reauth (no toggle) — OAuth API credentials.
    ALWAYS_REAUTH_SETTING_NAMES = %w[
      oauth_consumer_key
      oauth_consumer_secret
    ].freeze

    META_ACTION_KEY = 'settings.reauthentication.update'
    OAUTH_CREDENTIALS_ACTION_KEY = 'settings.oauth_credentials.update'

    ALWAYS_ON_ACTION_KEYS = [
      META_ACTION_KEY,
      OAUTH_CREDENTIALS_ACTION_KEY,
    ].freeze

    META_SETTING_NAMES = (
      ['reauthentication_window_minutes'] + ACTION_SETTINGS.values
    ).freeze

    module_function

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

    # Fail-secure: only explicit false disables a toggleable action policy.
    def policy_enabled?(action_key)
      return true if ALWAYS_ON_ACTION_KEYS.include?(action_key)

      setting_name = ACTION_SETTINGS[action_key]
      return true if setting_name.blank?

      Setting[setting_name] != false
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
