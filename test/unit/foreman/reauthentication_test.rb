# frozen_string_literal: true

require 'test_helper'

class Foreman::ReauthenticationTest < ActiveSupport::TestCase
  setup do
    @user = FactoryBot.create(:user, :with_mail)
    @session = {}
    @session[:user] = @user.id
  end

  test 'marks and checks recent authentication within window' do
    Foreman::Reauthentication.mark_authenticated!(@session, @user)
    assert Foreman::Reauthentication.recently_authenticated?(@session)
  end

  test 'expired window is not recent' do
    Setting[:reauthentication_window_minutes] = 5
    Foreman::Reauthentication.mark_authenticated!(@session, @user)
    @session[Foreman::Reauthentication::SESSION_AT] = 10.minutes.ago.to_i
    refute Foreman::Reauthentication.recently_authenticated?(@session)
  end

  test 'actor mismatch invalidates recent auth' do
    Foreman::Reauthentication.mark_authenticated!(@session, @user)
    @session[:user] = FactoryBot.create(:user).id
    refute Foreman::Reauthentication.recently_authenticated?(@session)
  end

  test 'impersonation uses original actor for binding' do
    admin = FactoryBot.create(:user, :admin)
    @session[:user] = @user.id
    @session[:impersonated_by] = admin.id
    Foreman::Reauthentication.mark_authenticated!(@session, admin)
    assert_equal admin.id, Foreman::Reauthentication.real_actor_id(@session)
    assert Foreman::Reauthentication.recently_authenticated?(@session)
  end

  test 'api authenticated sessions are not interactive' do
    @session[:api_authenticated_session] = true
    refute Foreman::Reauthentication.interactive_session?(@session)
    refute Foreman::Reauthentication.required_for?('users.set_admin', session: @session)
  end

  test 'policy fail-secure when setting would be false only if explicit' do
    Setting[:require_reauth_users_set_admin] = false
    refute Foreman::Reauthentication.policy_enabled?('users.set_admin')
    Setting[:require_reauth_users_set_admin] = true
    assert Foreman::Reauthentication.policy_enabled?('users.set_admin')
  end

  test 'meta action always enabled' do
    assert Foreman::Reauthentication.policy_enabled?(Foreman::Reauthentication::META_ACTION_KEY)
  end

  test 'admin and disabled transition detection' do
    assert Foreman::Reauthentication.admin_transition?(@user, admin: true)
    refute Foreman::Reauthentication.admin_transition?(@user, admin: false)
    refute Foreman::Reauthentication.admin_transition?(@user, firstname: 'x')

    refute @user.disabled?
    assert Foreman::Reauthentication.disabled_transition?(@user, disabled: true)
    refute Foreman::Reauthentication.disabled_transition?(@user, disabled: false)
  end

  test 'marks_login_as_fresh for internal and ldap only' do
    assert Foreman::Reauthentication.marks_login_as_fresh?(@user)
    ldap_source = FactoryBot.create(:auth_source_ldap)
    ldap_user = FactoryBot.create(:user, auth_source: ldap_source)
    assert Foreman::Reauthentication.marks_login_as_fresh?(ldap_user)

    external = AuthSourceExternal.find_by(name: 'External') || FactoryBot.create(:auth_source_external)
    ext_user = FactoryBot.create(:user, auth_source: external)
    refute Foreman::Reauthentication.marks_login_as_fresh?(ext_user)
  end

  test 'clear removes session keys' do
    Foreman::Reauthentication.mark_authenticated!(@session, @user)
    Foreman::Reauthentication.clear!(@session)
    refute @session.key?(Foreman::Reauthentication::SESSION_AT)
    refute @session.key?(Foreman::Reauthentication::SESSION_ACTOR)
  end

  test 'window_minutes clamps invalid to safe default' do
    Setting[:reauthentication_window_minutes] = 5
    assert_equal 5, Foreman::Reauthentication.window_minutes
  end

  test 'meta_setting? recognizes policy settings' do
    assert Foreman::Reauthentication.meta_setting?('reauthentication_window_minutes')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_users_set_admin')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_users_destroy')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_users_create')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_personal_access_tokens_create')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_ssh_keys_create')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_ssh_keys_destroy')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_registration_commands_create')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_key_pairs_download')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_hosts_console')
    assert Foreman::Reauthentication.meta_setting?('require_reauth_compute_resources_vms_console')
    refute Foreman::Reauthentication.meta_setting?('idle_timeout')
    refute Foreman::Reauthentication.meta_setting?('oauth_consumer_key')
  end

  test 'oauth credential settings always require reauth and are not toggleable meta' do
    assert Foreman::Reauthentication.always_reauth_setting?('oauth_consumer_key')
    assert Foreman::Reauthentication.always_reauth_setting?('oauth_consumer_secret')
    assert Foreman::Reauthentication.policy_enabled?(Foreman::Reauthentication::OAUTH_CREDENTIALS_ACTION_KEY)
  end

  test 'phase3b policy fail-secure for ssh keys' do
    assert Foreman::Reauthentication.policy_enabled?('ssh_keys.create')
    Setting[:require_reauth_ssh_keys_create] = false
    refute Foreman::Reauthentication.policy_enabled?('ssh_keys.create')
  end

  test 'password_change_other only for other users with nonblank password' do
    User.current = @user
    refute Foreman::Reauthentication.password_change_other_transition?(@user, password: 'Secret1!ab')
    other = FactoryBot.create(:user)
    assert Foreman::Reauthentication.password_change_other_transition?(other, password: 'Secret1!ab')
    refute Foreman::Reauthentication.password_change_other_transition?(other, password: '')
    refute Foreman::Reauthentication.password_change_other_transition?(other, firstname: 'x')
  end

  test 'roles_transition detects actual role id changes' do
    role = Role.find_by_name('Viewer') || FactoryBot.create(:role)
    refute Foreman::Reauthentication.roles_transition?(@user, role_ids: @user.role_ids)
    assert Foreman::Reauthentication.roles_transition?(@user, role_ids: [@user.role_ids, role.id].flatten.uniq)
  end

  test 'supported_for local and ldap only' do
    assert Foreman::Reauthentication.supported_for?(@user)
    external = AuthSourceExternal.find_by(name: 'External') || FactoryBot.create(:auth_source_external)
    ext_user = FactoryBot.create(:user, auth_source: external)
    refute Foreman::Reauthentication.supported_for?(ext_user)
  end

  test 'phase2 policy fail-secure when setting missing uses require' do
    assert Foreman::Reauthentication.policy_enabled?('users.destroy')
    Setting[:require_reauth_users_destroy] = false
    refute Foreman::Reauthentication.policy_enabled?('users.destroy')
  end

  test 'operations registry covers action settings and mandatory keys' do
    assert_operator Foreman::Reauthentication::OPERATIONS.size, :>=, 20
    Foreman::Reauthentication::ACTION_SETTINGS.each_key do |key|
      assert Foreman::Reauthentication.registered_operation?(key), key
      refute Foreman::Reauthentication.mandatory_operation?(key), key
    end
    Foreman::Reauthentication::ALWAYS_ON_ACTION_KEYS.each do |key|
      assert Foreman::Reauthentication.mandatory_operation?(key), key
      assert Foreman::Reauthentication.policy_enabled?(key), key
      assert_equal :mandatory_enabled, Foreman::Reauthentication.effective_policy(key)
    end
  end

  test 'unknown operation is not registered and stays fail-closed enabled' do
    refute Foreman::Reauthentication.registered_operation?('evil.controller#destroy')
    refute Foreman::Reauthentication.registered_operation?('../../etc/passwd')
    assert Foreman::Reauthentication.policy_enabled?('evil.controller#destroy')
    assert_equal :unknown, Foreman::Reauthentication.effective_policy('evil.controller#destroy')
  end

  test 'mandatory setting names are locked' do
    Foreman::Reauthentication::MANDATORY_SETTING_NAMES.each do |name|
      assert Foreman::Reauthentication.mandatory_setting?(name), name
      assert Foreman::Reauthentication.meta_setting?(name), name
    end
  end

  test 'policy inventory lists enabled configurable and mandatory rows' do
    inventory = Foreman::Reauthentication.policy_inventory
    assert inventory.any? { |row| row[:mandatory] && row[:effective] == :mandatory_enabled }
    impersonate = inventory.find { |row| row[:key] == 'users.impersonate' }
    assert impersonate
    refute impersonate[:mandatory]
    assert_equal true, impersonate[:enabled]
  end

  test 'disabling configurable operation changes only reauth policy' do
    assert Foreman::Reauthentication.policy_enabled?('users.impersonate')
    Setting[:require_reauth_users_impersonate] = false
    refute Foreman::Reauthentication.policy_enabled?('users.impersonate')
    assert_equal :disabled, Foreman::Reauthentication.effective_policy('users.impersonate')
    # Mandatory and unrelated policies unchanged
    assert Foreman::Reauthentication.policy_enabled?(Foreman::Reauthentication::META_ACTION_KEY)
    assert Foreman::Reauthentication.policy_enabled?('users.destroy')
  ensure
    Setting[:require_reauth_users_impersonate] = true
  end
end
