# frozen_string_literal: true

require 'test_helper'

module Mutations
  module Settings
    class UpdateSettingReauthenticationTest < GraphQLQueryTestCase
      let(:admin) { users(:admin) }
      let(:context_user) { admin }
      let(:query) do
        <<-GRAPHQL
          mutation updateSettingMutation($name: String!, $value: String!) {
            updateSetting(input: { name: $name, value: $value }) {
              setting {
                name
                value
              }
              errors {
                path
                message
              }
            }
          }
        GRAPHQL
      end

      def interactive_session(fresh: false)
        session = {
          user: admin.id,
          api_authenticated_session: false,
        }
        if fresh
          session[Foreman::Reauthentication::SESSION_AT] = Time.now.utc.to_i
          session[Foreman::Reauthentication::SESSION_ACTOR] = admin.id
        end
        session
      end

      def machine_session
        {
          user: admin.id,
          api_authenticated_session: true,
        }
      end

      context 'reauthentication_window_minutes' do
        let(:variables) { { name: 'reauthentication_window_minutes', value: '10' } }
        setup { Setting[:reauthentication_window_minutes] = 5 }

        test 'stale interactive session is blocked and value unchanged' do
          context[:session] = interactive_session(fresh: false)
          assert_not_empty result['errors']
          err = result['errors'].first
          assert_match(/Re-authentication required/i, err['message'])
          assert_equal true, err.dig('extensions', 'reauthentication_required')
          assert_equal 'settings.reauthentication.update', err.dig('extensions', 'action')
          assert_equal 5, Setting[:reauthentication_window_minutes]
        end

        test 'fresh interactive session succeeds' do
          context[:session] = interactive_session(fresh: true)
          assert_empty result['errors']
          assert_equal 10, Setting[:reauthentication_window_minutes]
        end

        test 'missing freshness fails closed' do
          context[:session] = { user: admin.id, api_authenticated_session: false,
                                reauthenticated_at: nil, reauth_actor_id: nil }
          assert_not_empty result['errors']
          assert_equal 5, Setting[:reauthentication_window_minutes]
        end

        test 'machine api session can update without browser freshness' do
          context[:session] = machine_session
          assert_empty result['errors']
          assert_equal 10, Setting[:reauthentication_window_minutes]
        end
      end

      context 'require_reauth meta-gate self-protection' do
        let(:variables) { { name: 'require_reauth_users_create', value: 'false' } }
        setup { Setting[:require_reauth_users_create] = true }

        test 'stale session cannot disable require_reauth via GraphQL' do
          context[:session] = interactive_session(fresh: false)
          assert_not_empty result['errors']
          assert_equal true, Setting[:require_reauth_users_create]
        end

        test 'fresh session can update require_reauth toggle' do
          context[:session] = interactive_session(fresh: true)
          assert_empty result['errors']
          assert_equal false, Setting[:require_reauth_users_create]
        end
      end

      context 'oauth consumer secret stale' do
        let(:variables) { { name: 'oauth_consumer_secret', value: 'new-secret-value' } }

        test 'stale interactive session is blocked' do
          context[:session] = interactive_session(fresh: false)
          assert_not_empty result['errors']
          err = result['errors'].first
          assert_equal true, err.dig('extensions', 'reauthentication_required')
          assert_equal 'settings.oauth_credentials.update', err.dig('extensions', 'action')
        end
      end

      context 'oauth consumer key fresh' do
        let(:variables) { { name: 'oauth_consumer_key', value: 'new-consumer-key' } }

        test 'fresh interactive session succeeds' do
          context[:session] = interactive_session(fresh: true)
          assert_empty result['errors']
          assert_equal 'new-consumer-key', Setting[:oauth_consumer_key]
        end
      end

      context 'ordinary non-sensitive setting' do
        let(:variables) { { name: 'entries_per_page', value: '25' } }

        test 'stale interactive session may update ordinary settings' do
          context[:session] = interactive_session(fresh: false)
          assert_empty result['errors']
          assert_equal 25, Setting[:entries_per_page]
        end
      end

      context 'unauthorized actor' do
        let(:context_user) { FactoryBot.create(:user) }
        let(:variables) { { name: 'reauthentication_window_minutes', value: '10' } }
        setup { Setting[:reauthentication_window_minutes] = 5 }

        test 'authorization denial precedes reauth and leaves value unchanged' do
          context[:session] = interactive_session(fresh: false)
          assert_not_empty result['errors']
          assert_match(/Unauthorized/i, result['errors'].first['message'])
          refute result['errors'].first.dig('extensions', 'reauthentication_required')
          assert_equal 5, Setting[:reauthentication_window_minutes]
        end
      end

      context 'SecurityEvent' do
        let(:variables) { { name: 'reauthentication_window_minutes', value: '12' } }

        test 'stale authorized mutation emits exactly one REAUTH_REQUIRED' do
          context[:session] = interactive_session(fresh: false)
          context[:request_ip] = '203.0.113.10'
          events = []
          Foreman::SecurityEvent.stubs(:log).with do |**kwargs|
            events << kwargs
            true
          end
          assert_not_empty result['errors']
          reauth_events = events.select { |e| e[:event] == 'REAUTH_REQUIRED' }
          assert_equal 1, reauth_events.size
          assert_equal 'DENIED', reauth_events.first[:status]
          assert_equal admin.login, reauth_events.first[:actor]
          assert_equal 'settings.reauthentication.update', reauth_events.first[:target]
          refute_match(/password|secret|token/i, reauth_events.first[:details].to_s)
        end
      end
    end
  end
end
