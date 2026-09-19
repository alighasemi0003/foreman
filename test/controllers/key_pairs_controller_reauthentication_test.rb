# frozen_string_literal: true

require 'test_helper'

class KeyPairsControllerReauthenticationTest < ActionController::TestCase
  tests KeyPairsController

  setup do
    @admin = users(:admin)
    @admin.update_column(:has_active_session, true)
    Setting[:require_reauth_key_pairs_download] = true
    Setting[:require_reauth_key_pairs_recreate] = true
    Setting[:require_reauth_key_pairs_destroy] = true

    # fog provider gems are often excluded; force Libvirt available for factory validation.
    Foreman::Model::Libvirt.stubs(:available?).returns(true)
    @compute_resource = FactoryBot.create(:libvirt_cr)
    # Libvirt does not natively advertise :key_pair; stub STI class instances.
    Foreman::Model::Libvirt.any_instance.stubs(:capabilities).returns([:key_pair])
  end

  def stale_session
    { user: @admin.id, expires_at: 5.minutes.from_now }
  end

  def build_key_pair
    KeyPair.create!(
      name: "foreman-#{Foreman.uuid}",
      secret: "--- BEGIN RSA #{Foreman.uuid}",
      compute_resource: @compute_resource
    )
  end

  test 'download blocked when stale' do
    key = build_key_pair
    get :show, params: { compute_resource_id: @compute_resource.to_param, id: key.id },
               session: stale_session
    assert_match(/Re-authentication required/i, flash[:error].to_s)
    refute_equal key.secret, @response.body
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
    KeyPair.where(compute_resource_id: @compute_resource.id).delete_all
    Foreman::Model::Libvirt.any_instance.stubs(:recreate).returns(
      KeyPair.create!(name: "foreman-#{Foreman.uuid}", secret: 'shhh', compute_resource: @compute_resource)
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
