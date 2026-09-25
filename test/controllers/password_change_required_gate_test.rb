# frozen_string_literal: true

require 'test_helper'

class PasswordChangeRequiredGateTest < ActionController::TestCase
  tests DashboardController

  setup do
    @user = FactoryBot.create(:user, :with_mail,
                              password: 'Password1!', password_confirmation: 'Password1!',
                              password_change_required: true)
  end

  test 'forced user cannot browse dashboard and is redirected to password change' do
    get :index, session: set_session_user(@user)
    assert_redirected_to edit_user_path(@user)
    assert_match(/change your password/i, flash[:warning].to_s)
  end
end
