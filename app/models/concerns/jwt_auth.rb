module JwtAuth
  extend ActiveSupport::Concern

  included do
    has_one :jwt_secret, inverse_of: :user, dependent: :destroy

    def jwt_secret!
      existing = jwt_secret
      if existing&.persisted? && !existing.destroyed? && JwtSecret.exists?(id: existing.id)
        return existing
      end

      # After invalidate/delete_all the association may still hold a stale record.
      association(:jwt_secret).reset
      create_jwt_secret!
    end

    # expiration:  integer, eg: 4.hours.to_i
    # scope:       example: [{ controller: :registration, actions: [:global, :host] }]
    def jwt_token!(expiration: nil, scope: [])
      jwt_secret = jwt_secret!
      JwtToken.encode(self, jwt_secret.token, expiration: expiration, scope: scope).to_s
    end

    # Foreman JWTs are HMAC-signed with per-user JwtSecret.token.
    # Destroying the secret is the authoritative invalidation mechanism.
    def invalidate_jwt!
      JwtSecret.where(user_id: id).delete_all
      association(:jwt_secret).reset
      true
    end
  end

  class_methods do
    def invalidate_jwts_for!(user_ids)
      ids = Array(user_ids).map(&:to_i).uniq
      return 0 if ids.empty?

      deleted = JwtSecret.where(user_id: ids).delete_all
      ids.each do |uid|
        u = User.unscoped.find_by(id: uid)
        u&.association(:jwt_secret)&.reset
      end
      deleted
    end
  end
end
