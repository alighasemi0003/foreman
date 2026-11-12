# frozen_string_literal: true

require 'test_helper'

class UserPasswordHistoryTest < ActiveSupport::TestCase
  HISTORY_MSG = 'The new password cannot match a recently used password.'
  CURRENT_MSG = 'The new password must be different from the current password.'

  setup do
    @passwords = ['Password1!', 'Password2!', 'Password3!', 'Password4!', 'Password5!', 'Password6!']
    Setting[:password_history_length] = 3
    @user = FactoryBot.create(:user, :with_mail,
                              auth_source: auth_sources(:internal),
                              password: @passwords[0],
                              password_confirmation: @passwords[0])
  end

  teardown do
    Setting[:password_history_length] = 5
  end

  def change_password!(user, from, to)
    as_user user do
      user.current_password = from
      user.password = to
      user.password_confirmation = to
      assert user.save, user.errors.full_messages.to_sentence
    end
    user.reload
  end

  test 'first password creation leaves history empty' do
    assert_equal 0, @user.password_histories.count
  end

  test 'first password change archives outgoing hash only' do
    change_password!(@user, @passwords[0], @passwords[1])
    assert_equal 1, @user.password_histories.count
    row = @user.password_histories.first
    assert row.password_hash.present?
    assert row.password_salt.present?
    refute_equal @passwords[0], row.password_hash
    refute_match(/Password/, row.password_hash)
    assert row.matches_password?(@passwords[0])
    refute row.matches_password?(@passwords[1])
  end

  test 'current password reuse still rejected when history disabled' do
    Setting[:password_history_length] = 0
    as_user @user do
      @user.current_password = @passwords[0]
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      refute @user.valid?
      assert_includes @user.errors[:password], CURRENT_MSG
    end
  end

  test 'reusing most recent previous password is rejected' do
    change_password!(@user, @passwords[0], @passwords[1])
    as_user @user do
      @user.current_password = @passwords[1]
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      refute @user.valid?
      assert_includes @user.errors[:password], HISTORY_MSG
      refute_includes @user.errors.full_messages.join, @passwords[0]
    end
    assert_equal 1, @user.password_histories.count
  end

  test 'reusing any password within N is rejected' do
    change_password!(@user, @passwords[0], @passwords[1])
    change_password!(@user, @passwords[1], @passwords[2])
    change_password!(@user, @passwords[2], @passwords[3])
    # history: p2, p1, p0 (N=3); current p3
    as_user @user do
      @user.current_password = @passwords[3]
      @user.password = @passwords[1]
      @user.password_confirmation = @passwords[1]
      refute @user.valid?
      assert_includes @user.errors[:password], HISTORY_MSG
    end
  end

  test 'password outside configured history depth is allowed' do
    # N=3: after 4 changes current is p4; history p3,p2,p1 — p0 falls out
    change_password!(@user, @passwords[0], @passwords[1])
    change_password!(@user, @passwords[1], @passwords[2])
    change_password!(@user, @passwords[2], @passwords[3])
    change_password!(@user, @passwords[3], @passwords[4])
    assert_equal 3, @user.password_histories.count

    as_user @user do
      @user.current_password = @passwords[4]
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      assert @user.save, @user.errors.full_messages.to_sentence
    end
  end

  test 'new unique password is accepted and history grows then prunes' do
    change_password!(@user, @passwords[0], @passwords[1])
    change_password!(@user, @passwords[1], @passwords[2])
    change_password!(@user, @passwords[2], @passwords[3])
    change_password!(@user, @passwords[3], @passwords[4])
    assert_equal 3, @user.password_histories.count
    assert @user.matching_password?(@passwords[4])
  end

  test 'decreasing N prunes on next successful change' do
    change_password!(@user, @passwords[0], @passwords[1])
    change_password!(@user, @passwords[1], @passwords[2])
    change_password!(@user, @passwords[2], @passwords[3])
    assert_equal 3, @user.password_histories.count
    Setting[:password_history_length] = 1
    change_password!(@user, @passwords[3], @passwords[4])
    assert_equal 1, @user.password_histories.count
  end

  test 'zero history disables historical check but keeps current rejection' do
    change_password!(@user, @passwords[0], @passwords[1])
    Setting[:password_history_length] = 0
    as_user @user do
      @user.current_password = @passwords[1]
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      assert @user.save, @user.errors.full_messages.to_sentence
    end
    assert_equal 0, @user.password_histories.count
  end

  test 'invalid setting values are rejected' do
    setting = Setting.find_by_name('password_history_length')
    assert setting
    setting.value = -1
    refute_valid setting
    setting.value = 25
    refute_valid setting
    setting.value = 0
    assert_valid setting
    setting.value = 24
    assert_valid setting
  end

  test 'admin reset enforces history' do
    change_password!(@user, @passwords[0], @passwords[1])
    as_user users(:admin) do
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      refute @user.valid?
      assert_includes @user.errors[:password], HISTORY_MSG
    end
  end

  test 'failed validation does not mutate history' do
    change_password!(@user, @passwords[0], @passwords[1])
    before = @user.password_histories.pluck(:id).sort
    as_user @user do
      @user.current_password = @passwords[1]
      @user.password = @passwords[0]
      @user.password_confirmation = @passwords[0]
      refute @user.save
    end
    assert_equal before, @user.password_histories.pluck(:id).sort
    assert @user.reload.matching_password?(@passwords[1])
  end

  test 'profile update without password does not mutate history' do
    change_password!(@user, @passwords[0], @passwords[1])
    before = @user.password_histories.pluck(:id).sort
    @user.firstname = 'HistoryTest'
    assert @user.save, @user.errors.full_messages.to_sentence
    assert_equal before, @user.password_histories.pluck(:id).sort
  end

  test 'ldap users are unaffected' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.build(:user, :with_mail, auth_source: ldap)
    refute user.manage_password?
    assert user.valid?, user.errors.full_messages.to_sentence
    assert_equal 0, user.password_histories.size
  end

  test 'user deletion removes history rows' do
    change_password!(@user, @passwords[0], @passwords[1])
    id = @user.id
    assert UserPasswordHistory.where(user_id: id).exists?
    as_admin { @user.destroy! }
    refute UserPasswordHistory.where(user_id: id).exists?
  end
end
