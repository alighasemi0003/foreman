# frozen_string_literal: true

require 'test_helper'

class UserPasswordComplexityTest < ActiveSupport::TestCase
  COMPLEXITY_MSG = 'Complexity requirement not met. Length should be 8 or more and include: 1 letter, 1 number and 1 special character.'

  setup do
    User.current = users(:admin)
    @user = FactoryBot.build(:user, :mail => 'foo@bar.com')
  end

  test 'accepts password with letter, number, special character and minimum length' do
    @user.password = 'Password1!'

    assert @user.valid?, @user.errors.full_messages.to_sentence
  end

  test 'rejects password without a number' do
    @user.password = 'Password!'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'rejects password without a letter' do
    @user.password = '12345678!'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'rejects password without a special character' do
    @user.password = 'Password1'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'rejects password shorter than 8 characters' do
    @user.password = 'Pass1!'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'rejects 7 characters with special' do
    @user.password = 'Abcde1!'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'rejects 8 characters without special' do
    @user.password = 'Abcdefg1'

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'accepts 8 characters with special' do
    @user.password = 'Abcdef1!'

    assert @user.valid?, @user.errors.full_messages.to_sentence
  end

  test 'accepts longer password with special' do
    @user.password = 'LongerPass99@'

    assert @user.valid?, @user.errors.full_messages.to_sentence
  end

  test 'representative special characters are accepted' do
    %w[! @ # $ % & * _].each do |special|
      @user.password = "Abcdef1#{special}"
      assert @user.valid?, "expected special #{special.inspect} to be accepted: #{@user.errors.full_messages}"
    end
  end

  test 'whitespace alone does not count as special character' do
    @user.password = 'Abcdef1 '

    refute @user.valid?
    assert_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'skips complexity check when password is blank' do
    @user.password = ''
    @user.valid?

    # New users still need a password_hash; complexity itself must not fire on blank.
    refute_includes @user.errors[:password], COMPLEXITY_MSG
  end

  test 'blank password on unrelated edit does not trigger complexity' do
    user = FactoryBot.create(:user, :mail => 'edit@example.com')
    user.firstname = 'Updated'
    user.password = ''

    assert user.save, user.errors.full_messages.to_sentence
  end

  test 'weak password on edit is rejected' do
    user = FactoryBot.create(:user, :mail => 'edit2@example.com')
    user.password = 'weakpass'

    refute user.valid?
    assert_includes user.errors[:password], COMPLEXITY_MSG
  end

  test 'strong password on edit is accepted' do
    user = FactoryBot.create(:user, :mail => 'edit3@example.com')
    user.password = 'NewPass1!'
    user.password_confirmation = 'NewPass1!'

    assert user.save, user.errors.full_messages.to_sentence
  end

  test 'mismatched confirmation is rejected even when complexity is met' do
    @user.password = 'Abcdef1!'
    @user.password_confirmation = 'Different1!'

    refute @user.valid?
    assert @user.errors[:password_confirmation].present?
  end

  test 'LDAP users are not subject to local password complexity' do
    ldap = FactoryBot.build(:user, :mail => 'ldap@example.com', :auth_source => auth_sources(:one), :password => 'weakpass')
    refute ldap.manage_password?
    assert ldap.valid?, ldap.errors.full_messages.to_sentence
  end

  test 'legacy user with existing hash can login and save unrelated attrs without rechecking password' do
    user = FactoryBot.create(:user, :mail => 'legacy@example.com', :password => 'Password1!')
    # Simulate subsequent non-password update without reassigning password
    user.reload
    user.firstname = 'Legacy'
    user.password = nil

    assert user.save, user.errors.full_messages.to_sentence
    assert User.try_to_login(user.login, 'Password1!')
  end

  test 'compliant? helper matches policy' do
    assert UserPasswordComplexity.compliant?('Abcdef1!')
    refute UserPasswordComplexity.compliant?('weakpass')
    refute UserPasswordComplexity.compliant?('Abcdef1 ')
    refute UserPasswordComplexity.compliant?('Abcde1!')
  end
end
