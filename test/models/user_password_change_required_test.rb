# frozen_string_literal: true

require 'test_helper'

class UserPasswordChangeRequiredTest < ActiveSupport::TestCase
  test 'default password_change_required is false before validation' do
    user = FactoryBot.build(:user, :with_mail)
    assert_equal false, user.password_change_required
  end

  test 'sanitize clears force flag for LDAP auth sources' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.build(:user, :with_mail, auth_source: ldap, password_change_required: true)
    user.skip_mandatory_password_change = false
    user.valid?
    refute user.password_change_required?
  end

  test 'new internal user is forced to change password even when false is assigned' do
    user = User.new(
      login: "pcr#{Foreman.uuid[0..7]}",
      mail: 'pcr@example.com',
      auth_source: auth_sources(:internal),
      password: 'Password1!',
      password_confirmation: 'Password1!',
      password_change_required: false
    )
    assert user.valid?, user.errors.full_messages.to_sentence
    assert user.password_change_required?
  end

  test 'internal auth source keeps force flag on create' do
    user = User.new(
      login: "pcr2#{Foreman.uuid[0..7]}",
      mail: 'pcr2@example.com',
      auth_source: auth_sources(:internal),
      password: 'Password1!',
      password_confirmation: 'Password1!',
      password_change_required: true
    )
    assert user.valid?, user.errors.full_messages.to_sentence
    assert user.password_change_required?
  end

  test 'admin password assignment re-enables force flag' do
    user = FactoryBot.create(:user, :with_mail, auth_source: auth_sources(:internal))
    refute user.password_change_required?

    User.current = users(:admin)
    user.password = 'TempReset9!'
    user.password_confirmation = 'TempReset9!'
    assert user.save, user.errors.full_messages.to_sentence
    assert user.password_change_required?
  ensure
    User.current = nil
  end

  test 'self password change does not re-enable force flag' do
    user = FactoryBot.create(:user, :with_mail, auth_source: auth_sources(:internal))
    refute user.password_change_required?

    User.current = user
    user.password = 'CompletelyNew9!'
    user.password_confirmation = 'CompletelyNew9!'
    user.current_password = 'Password1!'
    assert user.save, user.errors.full_messages.to_sentence
    refute user.password_change_required?
  ensure
    User.current = nil
  end

  test 'mass assignment cannot clear pending force flag' do
    user = FactoryBot.create(:user, :with_mail, :require_password_change,
                             auth_source: auth_sources(:internal))
    assert user.password_change_required?

    user = User.unscoped.find(user.id)
    user.password_change_required = false
    user.firstname = 'Updated'
    assert user.save, user.errors.full_messages.to_sentence
    assert user.reload.password_change_required?
  end

  test 'skip_mandatory_password_change allows bootstrap without force' do
    user = User.new(
      login: "boot#{Foreman.uuid[0..7]}",
      mail: 'boot@example.com',
      auth_source: auth_sources(:internal),
      password: 'Password1!',
      password_confirmation: 'Password1!'
    )
    user.skip_mandatory_password_change = true
    assert user.valid?, user.errors.full_messages.to_sentence
    refute user.password_change_required?
  end
end
