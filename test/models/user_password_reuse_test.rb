# frozen_string_literal: true

require 'test_helper'

class UserPasswordReuseTest < ActiveSupport::TestCase
  REUSE_MSG = 'The new password must be different from the current password.'

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              auth_source: auth_sources(:internal),
                              password: @password,
                              password_confirmation: @password)
  end

  test 'self change rejects new password equal to current password' do
    as_user @user do
      @user.current_password = @password
      @user.password = @password
      @user.password_confirmation = @password
      refute @user.valid?
      assert_includes @user.errors[:password], REUSE_MSG
      refute @user.errors.full_messages.join.include?(@password)
    end
  end

  test 'self change accepts a different complexity-compliant password' do
    as_user @user do
      @user.current_password = @password
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      assert @user.save, @user.errors.full_messages.to_sentence
      assert @user.matching_password?('Password2!')
    end
  end

  test 'self change still enforces complexity when password differs' do
    as_user @user do
      @user.current_password = @password
      @user.password = 'weakpass'
      @user.password_confirmation = 'weakpass'
      refute @user.valid?
      assert @user.errors[:password].any? { |m| m.include?('Complexity requirement') }
    end
  end

  test 'LDAP users are unaffected by password reuse validation' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.build(:user, :with_mail, auth_source: ldap,
                            password: 'Password1!', password_confirmation: 'Password1!')
    refute user.manage_password?
    # ensure_new_password_differs_from_current is gated on manage_password?
    assert user.valid?, user.errors.full_messages.to_sentence
  end

  test 'admin reset of another user rejects reuse of that user current password' do
    as_user users(:admin) do
      @user.password = @password
      @user.password_confirmation = @password
      refute @user.valid?
      assert_includes @user.errors[:password], REUSE_MSG
    end
  end

  test 'admin reset of another user accepts a different password' do
    as_user users(:admin) do
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      assert @user.save, @user.errors.full_messages.to_sentence
    end
  end
end
