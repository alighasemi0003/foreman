# frozen_string_literal: true

require 'test_helper'

class AuthSourceLdapsControllerReauthenticationTest < ActionController::TestCase
  tests AuthSourceLdapsController

  setup do
    @admin = users(:admin)
    @ldap = FactoryBot.create(:auth_source_ldap)
    Setting[:require_reauth_auth_sources_update] = true
    Setting[:require_reauth_auth_sources_create] = true
    Setting[:require_reauth_auth_sources_destroy] = true
  end

  test 'update blocked without recent auth and not persisted' do
    original = @ldap.name
    put :update, params: { id: @ldap.id, auth_source_ldap: { name: "#{original}-x" } },
                 session: { user: @admin.id, expires_at: 5.minutes.from_now }
    assert_response :redirect
    assert_equal original, @ldap.reload.name
  end

  test 'update allowed with recent auth' do
    original = @ldap.name
    put :update, params: { id: @ldap.id, auth_source_ldap: { name: "#{original}-y" } },
                 session: set_session_user(@admin)
    assert_response :redirect
    assert_equal "#{original}-y", @ldap.reload.name
  end

  test 'create blocked without recent auth' do
    assert_no_difference('AuthSourceLdap.unscoped.count') do
      post :create, params: { auth_source_ldap: FactoryBot.attributes_for(:auth_source_ldap) },
                    session: { user: @admin.id, expires_at: 5.minutes.from_now }
    end
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'create allowed with recent auth' do
    assert_difference('AuthSourceLdap.unscoped.count', 1) do
      post :create, params: { auth_source_ldap: FactoryBot.attributes_for(:auth_source_ldap) },
                    session: set_session_user(@admin)
    end
    assert_response :redirect
  end

  test 'destroy blocked without recent auth' do
    lid = @ldap.id
    delete :destroy, params: { id: lid },
                     session: { user: @admin.id, expires_at: 5.minutes.from_now }
    assert_response :redirect
    assert AuthSourceLdap.unscoped.exists?(lid)
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'destroy allowed with recent auth for local actor' do
    lid = @ldap.id
    delete :destroy, params: { id: lid }, session: set_session_user(@admin)
    assert_response :redirect
    refute AuthSourceLdap.unscoped.exists?(lid)
  end
end
