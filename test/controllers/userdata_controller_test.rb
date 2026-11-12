require 'test_helper'

class UserdataControllerTest < ActionController::TestCase
  context '#user-data' do
    let(:organization) { FactoryBot.create(:organization) }
    let(:tax_location) { FactoryBot.create(:location) }
    let(:user_data_content) { 'template content user_data' }
    let(:cloud_init_content) { 'template content cloud-init' }
    let(:user_data_template_kind) do
      TemplateKind.where(name: 'user_data').first || FactoryBot.create(:template_kind, name: 'user_data')
    end
    let(:cloud_init_template_kind) { FactoryBot.create(:template_kind, name: 'cloud-init') }
    let(:user_data_template) do
      FactoryBot.create(
        :provisioning_template,
        template_kind: user_data_template_kind,
        template: user_data_content,
        locations: [tax_location],
        organizations: [organization]
      )
    end
    let(:cloud_init_template) do
      FactoryBot.create(
        :provisioning_template,
        template_kind: cloud_init_template_kind,
        template: cloud_init_content,
        locations: [tax_location],
        organizations: [organization]
      )
    end
    let(:os) do
      FactoryBot.create(
        :operatingsystem,
        :with_associations,
        family: 'Redhat',
        provisioning_templates: [
          user_data_template,
          cloud_init_template,
        ]
      )
    end
    let(:host) do
      FactoryBot.create(
        :host,
        :managed,
        operatingsystem: os,
        organization: organization,
        location: tax_location
      )
    end

    setup do
      FactoryBot.create(
        :os_default_template,
        template_kind: user_data_template_kind,
        provisioning_template: user_data_template,
        operatingsystem: os
      )
      @request.remote_ip = host.ip
    end

    context 'with user_data template' do
      test 'should get rendered userdata template' do
        get :userdata
        assert_response :success
        assert_equal user_data_content, @response.body
      end

      test 'authorized host receives userdata with own mac in path' do
        get :userdata, params: { mac: host.mac }
        assert_response :success
        assert_equal user_data_content, @response.body
      end

      context 'with unknown ip address' do
        test 'should display an error' do
          @request.remote_ip = '198.51.100.1'
          get :userdata
          assert_response :not_found
          assert_includes @response.body, 'Could not find host for request 198.51.100.1'
        end
      end

      test 'spoofed mac from unrelated ip cannot read another host userdata' do
        victim = host
        @request.remote_ip = '198.51.100.50'
        get :userdata, params: { mac: victim.mac }
        assert_response :not_found
        refute_includes @response.body, user_data_content
        refute_includes @response.body, victim.name
      end

      test 'cross-host mac with attacker host ip is rejected' do
        attacker = FactoryBot.create(
          :host,
          :managed,
          operatingsystem: os,
          organization: organization,
          location: tax_location
        )
        @request.remote_ip = attacker.ip
        get :userdata, params: { mac: host.mac }
        assert_response :not_found
        refute_includes @response.body, user_data_content
      end

      test 'valid host token authorizes userdata without matching ip' do
        host.create_token(:value => Foreman.uuid, :expires => Time.now.utc + 5.minutes)
        @request.remote_ip = '198.51.100.77'
        get :userdata, params: { token: host.token.value }
        assert_response :success
        assert_equal user_data_content, @response.body
      end

      test 'expired host token is rejected' do
        host.create_token(:value => Foreman.uuid, :expires => Time.now.utc - 1.minute)
        @request.remote_ip = '198.51.100.77'
        get :userdata, params: { token: host.token.value }
        assert_response :not_found
        refute_includes @response.body, user_data_content
      end

      test 'invalid host token is rejected' do
        @request.remote_ip = host.ip
        get :userdata, params: { token: 'not-a-real-token' }
        assert_response :not_found
        refute_includes @response.body, user_data_content
      end

      test 'spoof query param cannot select another host' do
        other = FactoryBot.create(
          :host,
          :managed,
          operatingsystem: os,
          organization: organization,
          location: tax_location
        )
        @request.remote_ip = '198.51.100.9'
        get :userdata, params: { spoof: other.ip }
        assert_response :not_found
        refute_includes @response.body, user_data_content
      end
    end

    context 'with cloud-init template' do
      setup do
        FactoryBot.create(
          :os_default_template,
          :template_kind => cloud_init_template_kind,
          :provisioning_template => cloud_init_template,
          :operatingsystem => os
        )
      end

      test 'should get rendered cloud-init template' do
        get :userdata
        assert_response :success
        assert_equal cloud_init_content, @response.body
      end
    end
  end

  context '#metadata' do
    let(:host) { FactoryBot.create(:host, :managed) }
    setup do
      @request.remote_ip = host.ip
    end

    test 'should get metadata of a host' do
      get :metadata
      assert_response :success
      response = @response.body
      parsed = YAML.safe_load(response)
      assert_equal host.mac, parsed['mac']
      assert_equal host.hostname, parsed['hostname']
    end

    test 'spoofed mac cannot read another host metadata' do
      @request.remote_ip = '198.51.100.60'
      get :metadata, params: { mac: host.mac }
      assert_response :not_found
      refute_includes @response.body, host.hostname
      refute_includes @response.body, host.mac.to_s
    end
  end
end
