# frozen_string_literal: true

require 'test_helper'

class UserAccountLockoutTest < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  setup do
    User.current = users(:admin)
    Setting[:account_lockout_attempts] = 5
    Setting[:account_lockout_window] = 15
    Setting[:account_lockout_duration] = 30
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
  end

  test 'correct password succeeds and clears lockout state' do
    @user.update_columns(failed_login_attempts: 2, failed_login_started_at: Time.current.utc, locked_until: nil)

    logged_in = User.try_to_login(@user.login, @password)
    assert_equal @user, logged_in
    @user.reload
    assert_equal 0, @user.failed_login_attempts
    assert_nil @user.failed_login_started_at
    assert_nil @user.locked_until
  end

  test 'fewer than threshold failures do not lock the account' do
    4.times do
      assert_nil User.try_to_login(@user.login, 'wrong-password')
    end

    @user.reload
    assert_equal 4, @user.failed_login_attempts
    refute @user.account_locked?
    assert_equal @user, User.try_to_login(@user.login, @password)
  end

  test 'threshold failures within window lock the account' do
    5.times do
      assert_nil User.try_to_login(@user.login, 'wrong-password')
    end

    @user.reload
    assert_equal 5, @user.failed_login_attempts
    assert @user.account_locked?
    assert @user.locked_until > Time.current.utc
  end

  test 'correct password is denied while account is locked' do
    5.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?

    AuthSourceInternal.any_instance.expects(:authenticate).never
    assert_nil User.try_to_login(@user.login, @password)
  end

  test 'account unlocks automatically after lock duration' do
    locked_at = Time.utc(2026, 6, 1, 12, 0, 0)
    travel_to locked_at do
      5.times { User.try_to_login(@user.login, 'wrong-password') }
      @user.reload
      assert @user.account_locked?
    end

    travel_to locked_at + 31.minutes do
      logged_in = User.try_to_login(@user.login, @password)
      assert_equal @user, logged_in
      @user.reload
      refute @user.account_locked?
      assert_equal 0, @user.failed_login_attempts
      assert_nil @user.locked_until
    end
  end

  test 'successful login before threshold resets the counter' do
    3.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert_equal 3, @user.failed_login_attempts

    assert_equal @user, User.try_to_login(@user.login, @password)
    @user.reload
    assert_equal 0, @user.failed_login_attempts
    assert_nil @user.failed_login_started_at
    assert_nil @user.locked_until
  end

  test 'failures outside the window start a new counter' do
    started = Time.utc(2026, 6, 1, 12, 0, 0)
    travel_to started do
      3.times { User.try_to_login(@user.login, 'wrong-password') }
      @user.reload
      assert_equal 3, @user.failed_login_attempts
    end

    travel_to started + 16.minutes do
      assert_nil User.try_to_login(@user.login, 'wrong-password')
      @user.reload
      assert_equal 1, @user.failed_login_attempts
      refute @user.account_locked?
    end
  end

  test 'failures accumulate on the account regardless of client IP context' do
    # Account lockout is keyed by user record in DB, not by request IP.
    5.times do
      assert_nil User.try_to_login(@user.login, 'wrong-password')
    end
    @user.reload
    assert @user.account_locked?

    # Simulating another node/IP still sees the same locked account state.
    other = User.unscoped.find(@user.id)
    assert other.account_locked?
    assert_nil User.try_to_login(@user.login, @password)
  end

  test 'locking one user does not lock another user' do
    other = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
    5.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?

    other.reload
    refute other.account_locked?
    assert_equal other, User.try_to_login(other.login, @password)
  end

  test 'lockout state is persisted in the database not rails cache' do
    5.times { User.try_to_login(@user.login, 'wrong-password') }
    Rails.cache.clear

    reloaded = User.unscoped.find(@user.id)
    assert reloaded.account_locked?
    assert_equal 5, reloaded.failed_login_attempts
    assert reloaded.locked_until.present?
  end

  test 'locked and failed logins return the same nil result as wrong credentials' do
    assert_nil User.try_to_login(@user.login, 'wrong-password')
    4.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?

    assert_nil User.try_to_login(@user.login, @password)
    assert_nil User.try_to_login(@user.login, 'wrong-password')
    assert_nil User.try_to_login('missing-user-xyz', 'whatever')
  end

  test 'LDAP users are not subject to local account lockout counters' do
    ldap_user = users(:one)
    assert ldap_user.auth_source.is_a?(AuthSourceLdap)

    AuthSourceLdap.any_instance.stubs(:authenticate).returns(false)
    6.times { User.try_to_login(ldap_user.login, 'wrong-password') }

    ldap_user.reload
    assert_equal 0, ldap_user.failed_login_attempts
    assert_nil ldap_user.locked_until
    refute ldap_user.account_locked?
  end

  test 'successful password change clears lockout state' do
    5.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?

    User.current = @user
    @user.password = 'Newpass1!'
    @user.password_confirmation = 'Newpass1!'
    @user.current_password = @password
    assert @user.save, @user.errors.full_messages.to_sentence

    @user.reload
    refute @user.account_locked?
    assert_equal 0, @user.failed_login_attempts
    assert_nil @user.locked_until
    assert_equal @user, User.try_to_login(@user.login, 'Newpass1!')
  end

  test 'concurrent failed logins do not lose counter updates' do
    instances = Array.new(5) { User.unscoped.find(@user.id) }
    instances.each(&:register_failed_login!)

    @user.reload
    assert_equal 5, @user.failed_login_attempts
    assert @user.account_locked?
  end

  test 'API password authentication path respects account lockout' do
    5.times { User.try_to_login(@user.login, 'wrong-password', true) }
    @user.reload
    assert @user.account_locked?

    assert_nil User.try_to_login(@user.login, @password, true)
  end

  test 'disabled remains independent from temporary account lockout' do
    locked_at = Time.utc(2026, 6, 1, 12, 0, 0)
    travel_to locked_at do
      5.times { User.try_to_login(@user.login, 'wrong-password') }
      @user.reload
      assert @user.account_locked?
      refute @user.disabled?
    end

    travel_to locked_at + 31.minutes do
      @user.clear_expired_account_lock!
      @user.reload
      refute @user.account_locked?
      refute @user.disabled?
    end
  end

  test 'valid PAT still authenticates while password account is locked' do
    token_value = User.as(@user) do
      token = FactoryBot.create(:personal_access_token, :user => @user)
      value = token.generate_token
      assert token.save, token.errors.full_messages.to_sentence
      value
    end

    5.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?

    assert PersonalAccessToken.authenticate_user(@user, token_value), 'PAT should authenticate independently of password lockout'

    logged_in = User.try_to_login(@user.login, token_value, true)
    assert_equal @user, logged_in
    @user.reload
    assert @user.account_locked?, 'PAT auth must not clear password lockout state'
  end

  test 'non-password attribute updates do not clear lockout state' do
    5.times { User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?
    locked_until = @user.locked_until

    @user.update!(firstname: 'UpdatedName')
    @user.reload
    assert @user.account_locked?
    assert_equal locked_until.to_i, @user.locked_until.to_i
    assert_equal 5, @user.failed_login_attempts
  end

  test 'settings control threshold window and duration' do
    Setting[:account_lockout_attempts] = 2
    Setting[:account_lockout_window] = 10
    Setting[:account_lockout_duration] = 45

    locked_at = Time.utc(2026, 6, 1, 12, 0, 0)
    travel_to locked_at do
      2.times { User.try_to_login(@user.login, 'wrong-password') }
      @user.reload
      assert @user.account_locked?
      assert_in_delta (locked_at + 45.minutes).to_i, @user.locked_until.to_i, 2
    end
  end

  test 'account lockout settings reject non-positive values' do
    %w[account_lockout_attempts account_lockout_window account_lockout_duration].each do |name|
      setting = Setting.find_by_name(name)
      assert setting, "expected setting #{name} to exist"

      setting.value = 0
      refute_valid setting, :value, "must be greater than 0"

      setting.value = -1
      refute_valid setting, :value, "must be greater than 0"

      setting.value = 1
      assert_valid setting
    end
  end

  test 'IP bruteforce protection remains independent from account lockout' do
    previous = Setting[:failed_login_attempts_limit]
    Setting[:failed_login_attempts_limit] = 3
    begin
      protection = Foreman::BruteforceProtection.new(request_ip: '203.0.113.50')
      3.times { protection.count_login_failure }
      assert protection.bruteforce_attempt?

      other_user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
      refute other_user.account_locked?
      assert_equal other_user, User.try_to_login(other_user.login, @password)

      5.times { User.try_to_login(@user.login, 'wrong-password') }
      @user.reload
      assert @user.account_locked?

      other_ip = Foreman::BruteforceProtection.new(request_ip: '203.0.113.51')
      refute other_ip.bruteforce_attempt?
      assert_nil User.try_to_login(@user.login, @password)
    ensure
      Setting[:failed_login_attempts_limit] = previous
      Rails.cache.delete('failed_login_203.0.113.50')
      Rails.cache.delete('failed_login_203.0.113.51')
    end
  end
end
