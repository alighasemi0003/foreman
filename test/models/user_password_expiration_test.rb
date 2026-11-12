# frozen_string_literal: true

require 'test_helper'

class UserPasswordExpirationTest < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    Setting[:password_max_age] = 0
  end

  teardown do
    Setting[:password_max_age] = 0
  end

  test 'creating a local user stamps password_changed_at' do
    assert_not_nil @user.password_changed_at
  end

  test 'disabled policy never expires password' do
    Setting[:password_max_age] = 0
    @user.update_columns(password_changed_at: 10.years.ago.utc)
    refute @user.password_expired?
    refute @user.password_change_required?
  end

  test 'password within max age allows normal access predicate' do
    Setting[:password_max_age] = 90
    @user.update_columns(password_changed_at: Time.now.utc)
    refute @user.password_expired?
    refute @user.password_change_required?
  end

  test 'password past max age requires change' do
    Setting[:password_max_age] = 30
    @user.update_columns(password_changed_at: 31.days.ago.utc)
    assert @user.password_expired?
    assert @user.password_change_required?
  end

  test 'expiration boundary uses server utc time' do
    Setting[:password_max_age] = 10
    started = Time.utc(2026, 1, 1, 12, 0, 0)
    @user.update_columns(password_changed_at: started)

    travel_to started + 10.days - 1.second do
      refute @user.reload.password_expired?
    end

    travel_to started + 10.days do
      assert @user.reload.password_expired?
    end
  end

  test 'setting change affects expiration immediately' do
    @user.update_columns(password_changed_at: 20.days.ago.utc)
    Setting[:password_max_age] = 30
    refute @user.password_expired?
    Setting[:password_max_age] = 10
    assert @user.password_expired?
  end

  test 'successful password change refreshes password_changed_at' do
    old = 40.days.ago.utc
    @user.update_columns(password_changed_at: old)
    Setting[:password_max_age] = 30
    assert @user.password_expired?

    @user.password = 'CompletelyNew9!'
    @user.password_confirmation = 'CompletelyNew9!'
    @user.current_password = @password
    User.current = @user
    assert @user.save, @user.errors.full_messages.to_sentence
    assert_in_delta Time.now.utc.to_i, @user.reload.password_changed_at.to_i, 5
    refute @user.password_expired?
  ensure
    User.current = nil
  end

  test 'failed password change keeps old timestamp and expired state' do
    old = 40.days.ago.utc
    @user.update_columns(password_changed_at: old)
    Setting[:password_max_age] = 30

    @user.password = 'CompletelyNew9!'
    @user.password_confirmation = 'CompletelyNew9!'
    @user.current_password = 'wrong-current'
    User.current = @user
    refute @user.save
    assert_in_delta old.to_i, @user.reload.password_changed_at.to_i, 2
    assert @user.password_expired?
  ensure
    User.current = nil
  end

  test 'profile edit without password does not refresh age' do
    old = 5.days.ago.utc
    @user.update_columns(password_changed_at: old)
    Setting[:password_max_age] = 90
    # Drop in-memory password left by FactoryBot so this is a non-password update.
    @user.password = nil
    @user.password_confirmation = nil
    @user.firstname = 'Renamed'
    assert @user.save, @user.errors.full_messages.to_sentence
    assert_in_delta old.to_i, @user.reload.password_changed_at.to_i, 2
  end

  test 'current password reuse is rejected while expired' do
    Setting[:password_max_age] = 30
    @user.update_columns(password_changed_at: 40.days.ago.utc)
    @user.password = @password
    @user.password_confirmation = @password
    @user.current_password = @password
    User.current = @user
    refute @user.save
    assert_includes @user.errors[:password].join, 'different'
    assert @user.reload.password_expired?
  ensure
    User.current = nil
  end

  test 'ldap users are never password-expired by local policy' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.create(:user, :with_mail, auth_source: ldap)
    user.update_columns(password_changed_at: 10.years.ago.utc) if user.has_attribute?(:password_changed_at)
    Setting[:password_max_age] = 1
    refute user.password_expired?
    refute user.password_change_required?
  end

  test 'blank password_changed_at fails closed when policy enabled' do
    Setting[:password_max_age] = 90
    @user.update_columns(password_changed_at: nil)
    assert @user.password_expired?
    assert @user.password_change_required?
  end

  test 'password_max_age setting rejects negative and oversized values' do
    setting = Setting.find_by_name('password_max_age')
    assert setting

    setting.value = -1
    refute_valid setting

    setting.value = 3651
    refute_valid setting

    setting.value = 0
    assert_valid setting

    setting.value = 90
    assert_valid setting
  end

  test 'admin force flag remains independent of age' do
    Setting[:password_max_age] = 0
    @user.update_columns(password_change_required: true, password_changed_at: Time.now.utc)
    assert @user.password_change_required?
    refute @user.password_expired?
  end
end
