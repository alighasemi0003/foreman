# frozen_string_literal: true

require 'test_helper'

class UserPasswordChangeRequiredTest < ActiveSupport::TestCase
  test 'default password_change_required is false' do
    user = FactoryBot.build(:user, :with_mail)
    assert_equal false, user.password_change_required
  end

  test 'sanitize clears force flag for LDAP auth sources' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.build(:user, :with_mail, auth_source: ldap, password_change_required: true)
    user.valid?
    refute user.password_change_required?
  end

  test 'internal auth source can keep force flag' do
    user = FactoryBot.build(:user, :with_mail,
                            auth_source: auth_sources(:internal),
                            password: 'Password1!',
                            password_confirmation: 'Password1!',
                            password_change_required: true)
    assert user.valid?, user.errors.full_messages.to_sentence
    assert user.password_change_required?
  end
end
