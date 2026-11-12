# frozen_string_literal: true

require 'test_helper'

class PasswordHistoryForcedChangeTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:require_reauth_users_change_password] = false
    Setting[:password_history_length] = 3
    @password = 'Password1!'
    @next = 'Password2!'
    @reuse = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    # Establish one historical password
    as_user @user do
      @user.current_password = @password
      @user.password = @next
      @user.password_confirmation = @next
      assert @user.save
    end
    @user.update_columns(password_change_required: true)
  end

  teardown do
    Setting[:password_history_length] = 5
  end

  test 'forced password change rejects historical reuse' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: @next,
            password: @reuse,
            password_confirmation: @reuse
          }
        },
        session: set_session_user(@user)
    assert_template :password_change_required
    assert @user.reload.matching_password?(@next)
    assert_equal 1, @user.password_histories.count
  end

  test 'forced password change accepts unique password' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: @next,
            password: 'Password9!',
            password_confirmation: 'Password9!'
          }
        },
        session: set_session_user(@user)
    assert_redirected_to login_users_path
    assert @user.reload.matching_password?('Password9!')
  end
end

class PasswordHistoryApiUpdateTest < ActionController::TestCase
  tests Api::V2::UsersController

  setup do
    Setting[:require_reauth_users_change_password] = false
    Setting[:password_history_length] = 3
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password)
    as_user @user do
      @user.current_password = @password
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      assert @user.save
    end
  end

  teardown do
    Setting[:password_history_length] = 5
  end

  test 'API self password update rejects historical reuse' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: 'Password2!',
            password: @password,
            password_confirmation: @password
          }
        },
        session: set_session_user(@user)
    assert_response :unprocessable_entity
    body = ActiveSupport::JSON.decode(@response.body)
    assert_match(/recently used|different from the current/i, body.to_s)
    assert @user.reload.matching_password?('Password2!')
  end
end

class PasswordHistoryExpirationRenewalTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:require_reauth_users_change_password] = false
    Setting[:password_history_length] = 3
    Setting[:password_max_age] = 30
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password,
                              password_change_required: false)
    as_user @user do
      @user.current_password = @password
      @user.password = 'Password2!'
      @user.password_confirmation = 'Password2!'
      assert @user.save
    end
    @user.update_columns(password_changed_at: 40.days.ago.utc)
  end

  teardown do
    Setting[:password_history_length] = 5
    Setting[:password_max_age] = 0
  end

  test 'expired renewal rejects historical password' do
    put :update,
        params: {
          id: @user.id,
          user: {
            current_password: 'Password2!',
            password: @password,
            password_confirmation: @password
          }
        },
        session: set_session_user(@user)
    assert_template :password_change_required
    assert @user.reload.password_expired?
  end
end
