# frozen_string_literal: true

require 'test_helper'

class KeyPairsControllerReauthenticationTest < ActionController::TestCase
  tests KeyPairsController

  setup do
    @admin = users(:admin)
    Setting[:require_reauth_key_pairs_download] = true
    Setting[:require_reauth_key_pairs_recreate] = true
    Setting[:require_reauth_key_pairs_destroy] = true

    # Fog EC2 is often unavailable in CI; Libvirt is available but lacks :key_pair
    # capability — stub capability + association for download tests.
    Foreman::Model::Libvirt.stubs(:available?).returns(true)
    @compute_resource = FactoryBot.create(:libvirt_cr)
    Foreman::Model::Libvirt.any_instance.stubs(:capabilities).returns([:key_pair])
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  def build_key_pair
    key = KeyPair.create!(
      name: "foreman-#{Foreman.uuid}",
      secret: "TEST-ONLY-PEM-#{Foreman.uuid}",
      compute_resource_id: @compute_resource.id
    )
    Foreman::Model::Libvirt.any_instance.stubs(:key_pair).returns(key)
    key
  end

  test 'download blocked when stale and secret not returned' do
    key = build_key_pair
    get :show, params: { compute_resource_id: @compute_resource.to_param, id: key.id },
               session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
    refute_equal key.secret, @response.body
    refute_includes @response.body.to_s, key.secret
  end

  test 'download succeeds when fresh' do
    key = build_key_pair
    get :show, params: { compute_resource_id: @compute_resource.to_param, id: key.id },
               session: set_session_user(@admin)
    assert_response :success
    assert_equal key.secret, @response.body
  end

  test 'recreate blocked when stale' do
    Foreman::Model::Libvirt.any_instance.expects(:recreate).never
    post :create, params: { compute_resource_id: @compute_resource.to_param }, session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'recreate succeeds when fresh' do
    Foreman::Model::Libvirt.any_instance.stubs(:recreate).returns(
      KeyPair.create!(name: "foreman-#{Foreman.uuid}", secret: 'shhh-test-only', compute_resource_id: @compute_resource.id)
    )
    post :create, params: { compute_resource_id: @compute_resource.to_param },
                  session: set_session_user(@admin)
    assert_redirected_to @compute_resource
  end

  test 'destroy blocked when stale' do
    Foreman::Model::Libvirt.any_instance.expects(:delete_key_from_resource).never
    delete :destroy, params: { compute_resource_id: @compute_resource.to_param, id: 'foreman-key' },
                     session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
  end

  test 'destroy succeeds when fresh' do
    Foreman::Model::Libvirt.any_instance.stubs(:delete_key_from_resource).returns(true)
    delete :destroy, params: { compute_resource_id: @compute_resource.to_param, id: 'foreman-key' },
                     session: set_session_user(@admin)
    assert_redirected_to @compute_resource
  end

  test 'download setting OFF allows without recent auth' do
    Setting[:require_reauth_key_pairs_download] = false
    key = build_key_pair
    get :show, params: { compute_resource_id: @compute_resource.to_param, id: key.id },
               session: stale_session
    assert_response :success
    assert_equal key.secret, @response.body
  end
end
