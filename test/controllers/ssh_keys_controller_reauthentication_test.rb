# frozen_string_literal: true

require 'test_helper'

class SshKeysControllerReauthenticationTest < ActionController::TestCase
  tests SshKeysController

  let(:key) do
    'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIhRoL6PfBRs9YwW3r2/pYeLrxRzEZSUO3Go8JivxMsguEKjJ3byHDPvPpMHhKKSZD/HJY/A+2Ndqp0ElB+t2qs= foreman@example.com'
  end

  setup do
    @admin = users(:admin)
    @admin.update_column(:has_active_session, true)
    @user = FactoryBot.create(:user, :with_mail)
    Setting[:require_reauth_ssh_keys_create] = true
    Setting[:require_reauth_ssh_keys_destroy] = true
  end

  def stale_session(user = @admin)
    { user: user.id, expires_at: 5.minutes.from_now }
  end

  test 'create blocked when stale and no key persisted' do
    assert_no_difference('SshKey.unscoped.count') do
      post :create, params: { user_id: @user.id, ssh_key: { name: 'stale-key', key: key } },
                    session: stale_session
    end
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'create succeeds when fresh' do
    assert_difference('SshKey.unscoped.count', 1) do
      post :create, params: { user_id: @user.id, ssh_key: { name: 'fresh-key', key: key } },
                    session: set_session_user(@admin)
    end
    assert_redirected_to edit_user_path(@user)
  end

  test 'create setting OFF allows without recent auth' do
    Setting[:require_reauth_ssh_keys_create] = false
    assert_difference('SshKey.unscoped.count', 1) do
      post :create, params: { user_id: @user.id, ssh_key: { name: 'off-key', key: key } },
                    session: stale_session
    end
  end

  test 'unauthorized viewer cannot create even with fresh session' do
    viewer = users(:one)
    viewer.update_column(:has_active_session, true)
    assert_no_difference('SshKey.unscoped.count') do
      post :create, params: { user_id: @user.id, ssh_key: { name: 'denied-key', key: key } },
                    session: set_session_user(viewer)
    end
    assert_includes [403, 404], response.status
  end

  test 'external actor create is blocked when stale' do
    external = AuthSourceExternal.find_by(name: 'External') || FactoryBot.create(:auth_source_external)
    ext_admin = FactoryBot.create(:user, :admin, :with_mail, auth_source: external)
    ext_admin.update_column(:has_active_session, true)
    assert_no_difference('SshKey.unscoped.count') do
      post :create, params: { user_id: @user.id, ssh_key: { name: 'ext-key', key: key } },
                    session: stale_session(ext_admin)
    end
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'destroy blocked when stale and key remains' do
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    delete :destroy, params: { id: ssh_key.id, user_id: @user.id }, session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
    assert SshKey.exists?(ssh_key.id)
  end

  test 'destroy succeeds when fresh' do
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    delete :destroy, params: { id: ssh_key.id, user_id: @user.id }, session: set_session_user(@admin)
    assert_redirected_to edit_user_path(@user)
    refute SshKey.exists?(ssh_key.id)
  end

  test 'destroy setting OFF allows without recent auth' do
    Setting[:require_reauth_ssh_keys_destroy] = false
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    delete :destroy, params: { id: ssh_key.id, user_id: @user.id }, session: stale_session
    refute SshKey.exists?(ssh_key.id)
  end

  test 'unauthorized cannot destroy even with fresh session' do
    ssh_key = FactoryBot.create(:ssh_key, user: @user)
    viewer = users(:one)
    viewer.update_column(:has_active_session, true)
    delete :destroy, params: { id: ssh_key.id, user_id: @user.id }, session: set_session_user(viewer)
    assert_includes [403, 404], response.status
    assert SshKey.exists?(ssh_key.id)
  end
end
