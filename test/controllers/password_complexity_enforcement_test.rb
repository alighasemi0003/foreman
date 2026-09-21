# frozen_string_literal: true

require 'test_helper'

# Runtime bypass matrix: UI can be skipped; model/API must still reject weak passwords.
class PasswordComplexityEnforcementTest < ActionController::TestCase
  tests UsersController

  setup do
    setup_users
  end

  test 'admin create with weak password is rejected and not persisted' do
    post :create, params: {
      :user => {
        :login => 'weakbypass',
        :mail => 'weakbypass@example.com',
        :auth_source_id => auth_sources(:internal).id,
        :password => 'weakpass',
      },
    }, session: set_session_user

    assert_template :new
    refute User.unscoped.find_by_login('weakbypass')
  end

  test 'admin create with compliant password succeeds' do
    post :create, params: {
      :user => {
        :login => 'strongbypass',
        :mail => 'strongbypass@example.com',
        :auth_source_id => auth_sources(:internal).id,
        :password => 'Password1!',
      },
    }, session: set_session_user

    assert_redirected_to users_path
    assert User.unscoped.find_by_login('strongbypass')
  end

  test 'self password change rejects weak password' do
    user = FactoryBot.create(:user, :password => 'Password1!')
    put :update, params: {
      :id => user.id,
      :user => {
        :current_password => 'Password1!',
        :password => 'weakpass',
        :password_confirmation => 'weakpass',
      },
    }, session: set_session_user(user)

    assert_response :success
    assert_template :edit
    refute user.reload.matching_password?('weakpass')
  end

  test 'admin password change for another user rejects weak password' do
    user = FactoryBot.create(:user, :password => 'Password1!')
    put :update, params: {
      :id => user.id,
      :user => {
        :password => 'weakpass',
        :password_confirmation => 'weakpass',
      },
    }, session: set_session_user

    assert_response :success
    assert_template :edit
    refute user.reload.matching_password?('weakpass')
    assert user.reload.matching_password?('Password1!')
  end
end

class PasswordComplexityApiEnforcementTest < ActionController::TestCase
  tests Api::V2::UsersController

  test 'API create rejects weak password' do
    as_admin do
      post :create, params: {
        :user => {
          :login => 'apiweak',
          :mail => 'apiweak@example.com',
          :auth_source_id => auth_sources(:internal).id,
          :password => 'weakpass',
        },
      }, session: set_session_user
    end

    assert_response :unprocessable_entity
    refute User.unscoped.find_by_login('apiweak')
  end

  test 'API create accepts compliant password' do
    as_admin do
      post :create, params: {
        :user => {
          :login => 'apistrong',
          :mail => 'apistrong@example.com',
          :auth_source_id => auth_sources(:internal).id,
          :password => 'Password1!',
        },
      }, session: set_session_user
    end

    assert_response :created
    assert User.unscoped.find_by_login('apistrong')
  end
end
