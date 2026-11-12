# frozen_string_literal: true

module ForemanRegister
  class RegistrationToken
    VALID_BEFORE_ISSUING = 3600
    EXPIRE_AFTER_ISSUING = 24 * 3600
    ALGORITHM = 'HS256'

    class << self
      def encode(host, secret)
        payload = prepare_payload(host, secret)
        new JWT.encode(payload, secret, ALGORITHM)
      end

      private

      def prepare_payload(host, secret)
        expire_at = issued_at + EXPIRE_AFTER_ISSUING
        not_before = issued_at - VALID_BEFORE_ISSUING
        jwt_raw_id = [secret, issued_at].join(':')
        jwt_id = Digest::SHA256.hexdigest(jwt_raw_id)
        {
          host_id: host.id,
          iat: issued_at,
          jti: jwt_id,
          exp: expire_at,
          nbf: not_before,
        }
      end

      def issued_at
        Time.now.to_i
      end

      def host_id
        host.id
      end
    end

    attr_reader :token

    def initialize(token)
      @token = token
    end

    # Cryptographically verified decode — only this payload may authorize registration.
    def decode
      return nil if token.blank?
      return nil if secret.blank?

      payload = JWT.decode(token, secret, true, { algorithm: ALGORITHM })
      payload.first
    end

    def to_s
      token
    end

    private

    def secret
      @secret ||= find_secret
    end

    def find_secret
      host = ForemanRegister::RegistrationFacet.find_by(host_id: unsecure_payload['host_id'])&.host
      return unless host

      facet = host.registration_facet!
      facet.jwt_secret
    end

    def unsecure_payload
      # Inspection-only: extract host_id to locate the host-scoped jwt_secret.
      # Signature verification happens in #decode with that secret — do not trust
      # these claims for authorization.
      @unsecure_payload ||= JWT.decode(token, nil, false).first
    end
  end
end
