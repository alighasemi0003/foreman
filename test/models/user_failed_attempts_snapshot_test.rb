# frozen_string_literal: true

require 'test_helper'

class UserFailedAttemptsSnapshotTest < ActiveSupport::TestCase
  setup do
    Setting[:account_lockout_attempts] = 5
    Setting[:account_lockout_window] = 15
    Setting[:account_lockout_duration] = 30
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :password => @password, :password_confirmation => @password)
  end

  test 'post_successful_login snapshots attempts then resets counter' do
    @user.update_columns(failed_login_attempts: 2, failed_login_started_at: Time.current.utc, locked_until: nil)
    @user.post_successful_login
    assert_equal 2, @user.failed_attempts_before_login
    assert_equal 0, @user.reload.failed_login_attempts
  end

  test 'login event stores snapshot from user accessor' do
    @user.failed_attempts_before_login = 4
    event = UserLoginEvent.record_successful_login!(
      user: @user,
      remote_ip: '203.0.113.8',
      auth_method: 'password'
    )
    assert_equal 4, event.failed_attempts_before_login
  end

  test 'lockout after threshold still works with snapshot path' do
    5.times { assert_nil User.try_to_login(@user.login, 'wrong-password') }
    @user.reload
    assert @user.account_locked?
    assert_nil User.try_to_login(@user.login, @password)
    assert @user.reload.account_locked?
  end
end
