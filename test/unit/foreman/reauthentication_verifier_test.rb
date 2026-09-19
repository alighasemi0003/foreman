# frozen_string_literal: true

require 'test_helper'

class Foreman::Reauthentication::VerifierTest < ActiveSupport::TestCase
  setup do
    @user = FactoryBot.create(:user, :with_mail, password: 'Secret1!ab')
    @ip = '203.0.113.50'
  end

  test 'local correct password succeeds without try_to_login' do
    User.expects(:try_to_login).never
    result = Foreman::Reauthentication::Verifier.new(
      actor: @user, password: 'Secret1!ab', request_ip: @ip
    ).call
    assert_equal :success, result.status
  end

  test 'local wrong password fails and registers lockout attempt' do
    User.expects(:try_to_login).never
    result = Foreman::Reauthentication::Verifier.new(
      actor: @user, password: 'WrongPass1!', request_ip: @ip
    ).call
    assert_equal :authentication_failed, result.status
    assert_operator @user.reload.failed_login_attempts.to_i, :>=, 1
  end

  test 'local lockout after threshold' do
    Setting[:account_lockout_attempts] = 3
    Setting[:account_lockout_window] = 15
    Setting[:account_lockout_duration] = 30
    3.times do
      Foreman::Reauthentication::Verifier.new(
        actor: @user, password: 'WrongPass1!', request_ip: @ip
      ).call
    end
    assert @user.reload.account_locked?
    result = Foreman::Reauthentication::Verifier.new(
      actor: @user, password: 'Secret1!ab', request_ip: @ip
    ).call
    assert_equal :account_locked, result.status
  end

  test 'external auth source is unsupported' do
    external = AuthSourceExternal.first || FactoryBot.create(:auth_source_external)
    user = FactoryBot.create(:user, auth_source: external)
    result = Foreman::Reauthentication::Verifier.new(
      actor: user, password: 'anything', request_ip: @ip
    ).call
    assert_equal :reauthentication_unsupported, result.status
  end

  test 'ldap success does not call update_usergroups or try_to_login' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.create(:user, auth_source: ldap, login: 'ldapuser')
    ldap.expects(:authenticate).with('ldapuser', 'LdapPass1!').returns(firstname: 'A')
    ldap.expects(:update_usergroups).never
    User.expects(:try_to_login).never
    User.any_instance.expects(:update).never
    User.any_instance.expects(:post_successful_login).never

    result = Foreman::Reauthentication::Verifier.new(
      actor: user, password: 'LdapPass1!', request_ip: @ip
    ).call
    assert_equal :success, result.status
  end

  test 'ldap failure is generic' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.create(:user, auth_source: ldap, login: 'ldapuser')
    ldap.expects(:authenticate).returns(nil)
    result = Foreman::Reauthentication::Verifier.new(
      actor: user, password: 'bad', request_ip: @ip
    ).call
    assert_equal :authentication_failed, result.status
    assert_equal _('Authentication failed'), result.message
  end

  test 'ldap unavailable fails closed' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.create(:user, auth_source: ldap, login: 'ldapuser')
    ldap.expects(:authenticate).raises(Foreman::LdapException.new(StandardError.new('down'), 'down'))
    result = Foreman::Reauthentication::Verifier.new(
      actor: user, password: 'x', request_ip: @ip
    ).call
    assert_equal :authentication_failed, result.status
  end
end
