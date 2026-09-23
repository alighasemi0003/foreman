module Mutations
  module Settings
    class Update < BaseMutation
      graphql_name 'UpdateSettingMutation'
      description 'Updates a setting'

      # https://github.com/graphql/graphql-spec/blob/master/rfcs/InputUnion.md
      argument :id, ID, required: false
      argument :name, String, required: false
      argument :value, String, required: true

      field :errors, [Types::AttributeError], null: false
      field :setting, Types::Setting, description: 'Setting', null: true

      def self.resource_class
        SettingPresenter
      end

      def resolve(params)
        authorize!

        if params[:name]
          name = params[:name]
        else
          _, _, name = Foreman::GlobalId.decode(params[:id])
        end

        definition = Foreman.settings.find(name)
        validate_object(definition)

        ensure_sensitive_setting_reauthenticated!(definition.name)

        record = Foreman.settings.set_user_value(definition.name, params[:value])
        save_object(definition, record)
      end

      def save_object(definition, record)
        User.as(context[:current_user]) do
          errors = if record.save
                     []
                   else
                     map_errors_to_path(record)
                   end
          {
            :setting => definition,
            :errors => errors,
          }
        end
      end

      private

      def authorize!
        return if context[:current_user]&.can?(:edit_settings)

        raise GraphQL::ExecutionError.new(
          _('Unauthorized. You do not have the required permission %s.') % 'edit_settings'
        )
      end

      # Parity with Api::V2::SettingsController#ensure_meta_settings_reauthenticated!
      # Authorization already ran; machine/API sessions are excluded by
      # Foreman::Reauthentication.interactive_session?.
      def ensure_sensitive_setting_reauthenticated!(setting_name)
        action_key = Foreman::Reauthentication.action_key_for_setting(setting_name)
        return if action_key.nil?

        session = context[:session] || {}
        return unless Foreman::Reauthentication.required_for?(action_key, session: session)

        actor = Foreman::Reauthentication.real_actor(session)
        Foreman::SecurityEvent.log(
          event: 'REAUTH_REQUIRED',
          status: 'DENIED',
          level: :warn,
          actor: actor&.login,
          ip: context[:request_ip],
          target: action_key,
          details: "setting=#{setting_name}"
        )

        raise GraphQL::ExecutionError.new(
          _('Re-authentication required to perform this action.'),
          extensions: {
            'code' => 'REAUTHENTICATION_REQUIRED',
            'reauthentication_required' => true,
            'action' => action_key,
            'reauthentication_supported' => Foreman::Reauthentication.supported_for?(actor),
          }
        )
      end
    end
  end
end
