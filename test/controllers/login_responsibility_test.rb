# frozen_string_literal: true

require 'test_helper'

class UsersControllerLoginResponsibilityTest < ActionController::TestCase
  tests UsersController

  setup do
    Setting[:require_reauth_users_create] = false
    @password = 'Password1!'
    @user = FactoryBot.create(:user, :with_mail,
                              password: @password,
                              password_confirmation: @password)
  end

  test 'successful interactive login sets one-shot responsibility session flag' do
    post :login, params: { login: { login: @user.login, password: @password } }
    assert_response :redirect
    assert session[:show_login_responsibility], 'expected responsibility flag after UI login'
  end

  test 'failed login does not set responsibility session flag' do
    post :login, params: { login: { login: @user.login, password: 'WrongPass1!' } }
    refute session[:show_login_responsibility]
  end
end

class HostsControllerLoginResponsibilityTest < ActionController::TestCase
  tests HostsController

  setup do
    @user = users(:admin)
  end

  test 'authenticated page shows responsibility modal only when session flag is set' do
    get :index, session: set_session_user(@user).merge(show_login_responsibility: true)
    assert_response :success
    assert_match(/login-responsibility-modal/, response.body)
    assert_match(/Authorized use only/, response.body)
    assert_match(/Continue/, response.body)
    refute session[:show_login_responsibility]

    get :index, session: set_session_user(@user)
    assert_response :success
    refute_match(/login-responsibility-modal/, response.body)
  end

  test 'authenticated page without flag does not show responsibility modal' do
    get :index, session: set_session_user(@user)
    assert_response :success
    refute_match(/login-responsibility-modal/, response.body)
  end
end
