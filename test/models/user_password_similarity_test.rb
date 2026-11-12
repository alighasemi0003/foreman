# frozen_string_literal: true

require 'test_helper'

class UserPasswordSimilarityTest < ActiveSupport::TestCase
  SIMILARITY_MSG = 'The new password must differ from the current password by at least 4 characters.'
  REUSE_MSG = 'The new password must be different from the current password.'

  setup do
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              auth_source: auth_sources(:internal),
                              password: @password,
                              password_confirmation: @password)
  end

  test 'edit_distance is character based unicode levenshtein' do
    assert_equal 0, UserPasswordSimilarity.edit_distance('abc', 'abc')
    assert_equal 1, UserPasswordSimilarity.edit_distance('abc', 'abd')
    assert_equal 1, UserPasswordSimilarity.edit_distance('abc', 'ab')
    assert_equal 1, UserPasswordSimilarity.edit_distance('ab', 'abc')
    assert_equal 1, UserPasswordSimilarity.edit_distance('café', 'cafe')
    assert_equal 1, UserPasswordSimilarity.edit_distance('Password1!', 'Password2!')
    assert_equal 4, UserPasswordSimilarity.edit_distance('Password1!', 'Abcdword1!')
  end

  test 'identical current and new still rejected' do
    as_user @user do
      @user.current_password = @password
      @user.password = @password
      @user.password_confirmation = @password
      refute @user.valid?
      assert_includes @user.errors[:password], REUSE_MSG
    end
  end

  test 'difference of one two and three characters rejected when current_password present' do
    {
      'Password2!' => 1,
      'Password99!' => 2,
      'Password999!' => 3,
    }.each do |candidate, dist|
      assert_equal dist, UserPasswordSimilarity.edit_distance(@password, candidate), candidate
      assert UserPasswordComplexity.compliant?(candidate), candidate

      as_user @user do
        @user.reload
        @user.current_password = @password
        @user.password = candidate
        @user.password_confirmation = candidate
        refute @user.valid?, "expected reject dist=#{dist} for #{candidate}"
        assert_includes @user.errors[:password], SIMILARITY_MSG
        refute_includes @user.errors.full_messages.join(' '), @password
      end
    end
  end

  test 'difference of exactly four characters accepted by similarity rule' do
    candidate = 'Abcdword1!'
    assert_equal 4, UserPasswordSimilarity.edit_distance(@password, candidate)
    assert UserPasswordComplexity.compliant?(candidate)

    as_user @user do
      @user.current_password = @password
      @user.password = candidate
      @user.password_confirmation = candidate
      assert @user.save, @user.errors.full_messages.to_sentence
      assert @user.matching_password?(candidate)
    end
  end

  test 'greater difference accepted by similarity rule' do
    candidate = 'CompletelyNew9!'
    assert_operator UserPasswordSimilarity.edit_distance(@password, candidate), :>=, 4
    as_user @user do
      @user.current_password = @password
      @user.password = candidate
      @user.password_confirmation = candidate
      assert @user.save, @user.errors.full_messages.to_sentence
    end
  end

  test 'complexity still enforced when distance is sufficient' do
    candidate = 'zzzzzzzz'
    assert_operator UserPasswordSimilarity.edit_distance(@password, candidate), :>=, 4
    as_user @user do
      @user.current_password = @password
      @user.password = candidate
      @user.password_confirmation = candidate
      refute @user.valid?
      assert @user.errors[:password].any? { |m| m.include?('Complexity requirement') }
    end
  end

  test 'admin reset without current_password skips edit-distance but keeps identity' do
    as_user users(:admin) do
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      assert_nil @user.current_password
      assert @user.save, @user.errors.full_messages.to_sentence
    end
  end

  test 'admin reset still rejects exact reuse via hash' do
    as_user users(:admin) do
      @user.password = @password
      @user.password_confirmation = @password
      refute @user.valid?
      assert_includes @user.errors[:password], REUSE_MSG
    end
  end

  test 'LDAP users unaffected' do
    ldap = FactoryBot.create(:auth_source_ldap)
    user = FactoryBot.build(:user, :with_mail, auth_source: ldap,
                            password: 'Password1!', password_confirmation: 'Password1!')
    refute user.manage_password?
    assert user.valid?, user.errors.full_messages.to_sentence
  end

  test 'failed similarity validation does not change password hash' do
    before = @user.password_hash
    as_user @user do
      @user.current_password = @password
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      refute @user.save
    end
    assert_equal before, @user.reload.password_hash
  end

  test 'edit_distance bounds oversized inputs' do
    left = 'a' * 300
    right = 'b' * 300
    assert_equal 256, UserPasswordSimilarity.edit_distance(left, right)
  end
end
