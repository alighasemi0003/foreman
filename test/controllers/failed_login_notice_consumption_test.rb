# frozen_string_literal: true

require 'test_helper'

class FailedLoginNoticeConsumptionTest < ActionController::TestCase
  tests HostsController

  setup do
    @user = users(:admin)
    @other = users(:one)
  end

  test 'authenticated owner sees notice once then not again on refresh' do
    get :index, session: set_session_user(@user).merge(
      failed_login_notice_count: 3,
      failed_login_notice_user_id: @user.id
    )
    assert_response :success
    assert_equal(
      'There were 3 failed login attempts since your last successful login.',
      flash.now[:info] || flash[:info]
    )
    assert_nil session[:failed_login_notice_count]
    assert_nil session[:failed_login_notice_user_id]

    get :index, session: set_session_user(@user)
    assert_nil flash[:info]
  end

  test 'user cannot see another users failed-login notice' do
    get :index, session: set_session_user(@user).merge(
      failed_login_notice_count: 7,
      failed_login_notice_user_id: @other.id
    )
    assert_response :success
    assert_nil flash[:info]
    assert_nil session[:failed_login_notice_count]
  end

  test 'zero count does not show notice' do
    get :index, session: set_session_user(@user).merge(
      failed_login_notice_count: 0,
      failed_login_notice_user_id: @user.id
    )
    assert_nil flash[:info]
  end
end
