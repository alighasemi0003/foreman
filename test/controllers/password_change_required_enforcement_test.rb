# frozen_string_literal: true

require 'test_helper'

class PasswordChangeRequiredEnforcementTest < ActionController::TestCase
  tests HostsController

  setup do
    Setting[:require_reauth_users_create] = false
    Setting[:require_reauth_users_change_password] = false
    login = "pcrenf#{Foreman.uuid[0..7]}"
    as_admin do
      @user = User.create!(
        login: login,
        mail: "#{login}@example.com",
        auth_source: auth_sources(:internal),
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: true
      )
    end
  end

  test 'hosts redirects flagged user to password change edit' do
    get :index, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
    refute_match(%r{notification_recipients}, response.headers['Location'].to_s)
  end
end

class UsersIndexPasswordChangeRequiredTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:require_reauth_users_create] = false
    login = "pcru#{Foreman.uuid[0..7]}"
    as_admin do
      @user = User.create!(
        login: login,
        mail: "#{login}@example.com",
        auth_source: auth_sources(:internal),
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: true
      )
    end
  end

  test 'users index redirects flagged user to password change edit' do
    get :index, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
    refute_match(%r{notification_recipients}, response.headers['Location'].to_s)
  end
end

class NotificationRecipientsPasswordChangeRequiredTest < ActionController::TestCase
  tests NotificationRecipientsController

  setup do
    Setting[:require_reauth_users_create] = false
    login = "pcrn#{Foreman.uuid[0..7]}"
    as_admin do
      @user = User.create!(
        login: login,
        mail: "#{login}@example.com",
        auth_source: auth_sources(:internal),
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: true
      )
    end
  end

  test 'notification_recipients is forbidden during forced password change' do
    # API tests short-circuit authenticate when User.current is already set
    # (test helper defaults to admin). Force the flagged interactive user.
    as_user @user do
      get :index, session: set_session_user(@user)
      assert_response :forbidden
      refute_match(%r{notification_recipients}, response.headers['Location'].to_s)
    end
  end
end

class SshKeysUiPasswordChangeRequiredTest < ActionController::TestCase
  tests SshKeysController

  setup do
    Setting[:require_reauth_users_create] = false
    login = "pcrssh#{Foreman.uuid[0..7]}"
    as_admin do
      @user = User.create!(
        login: login,
        mail: "#{login}@example.com",
        auth_source: auth_sources(:internal),
        password: 'Password1!',
        password_confirmation: 'Password1!',
        password_change_required: true
      )
    end
  end

  test 'ssh_keys new redirects flagged user to password change edit' do
    get :new, params: { user_id: @user.id }, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
    refute_match(%r{notification_recipients}, response.headers['Location'].to_s)
  end
end
