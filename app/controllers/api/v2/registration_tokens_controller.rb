module Api
  module V2
    class RegistrationTokensController < V2::BaseController
      include Foreman::Controller::UserSelfEditing

      before_action :authenticate, :only => [:invalidate_jwt_tokens, :invalidate_jwt]

      def resource_class
        User
      end

      def resource_name(resource = resource_class.model_name.name.downcase)
        resource
      end

      def find_resource(permission = :view_users)
        editing_self? ? User.find(User.current.id) : User.authorized(permission).except_hidden.find(params[:id])
      end

      def action_permission
        case params[:action]
        when 'invalidate_jwt_tokens', 'invalidate_jwt'
          'edit'
        else
          super
        end
      end

      api :DELETE, '/users/:user_id/registration_tokens', N_("Invalidate all registration tokens for a specific user")
      description <<-DOC
      The user you specify will no longer be able to register hosts by using their JWTs.
      DOC
      param :user_id, String, :desc => N_("ID of the user"), :required => true

      def invalidate_jwt
        @user = find_resource(:edit_users)
        return unless ensure_reauthenticated!('users.invalidate_jwt')

        @user.invalidate_jwt!
        login = @user.login
        Foreman::SecurityEvent.log(
          event: 'JWT_INVALIDATE',
          status: 'SUCCESS',
          actor: User.current&.login,
          ip: request.remote_ip,
          target: login,
          details: 'Invalidated registration JWTs for user (API)'
        )
        render :json => { :message => _("Successfully invalidated registration tokens."), :user => login}, :status => :ok
      end

      api :DELETE, "/registration_tokens", N_("Invalidate all registration tokens for multiple users")
      param :search, String, :desc => N_("Search query that selects users for which registration tokens will be invalidated. Search query example: id ^ (2, 4, 6)"), :required => true
      description <<-DOC
      The users you specify will no longer be able to register hosts by using their JWTs.
      DOC

      def invalidate_jwt_tokens
        raise ::Foreman::Exception.new(N_("Please provide search parameter")) if params[:search].blank?
        return unless ensure_reauthenticated!('users.invalidate_jwt')

        @users = resource_scope_for_index(:permission => :edit_users).except_hidden.uniq
        if @users.blank?
          raise ::Foreman::Exception.new(N_("No record found for search '%s'"), params[:search]) end
        User.invalidate_jwts_for!(@users.map(&:id))
        login = @users.pluck(:login).to_sentence
        Foreman::SecurityEvent.log(
          event: 'JWT_INVALIDATE_SEARCH',
          status: 'SUCCESS',
          actor: User.current&.login,
          ip: request.remote_ip,
          target: login,
          details: 'Invalidated registration JWTs for searched users (API)'
        )
        render :json => { :message => _("Successfully invalidated registration tokens."), :users => login}, :status => :ok
      end
    end
  end
end
