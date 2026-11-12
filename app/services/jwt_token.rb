require 'jwt'
require 'base64'

class JwtToken < Struct.new(:token)
  # Foreman user JWTs are HMAC-signed with the per-user JwtSecret (symmetric).
  ALGORITHM = 'HS256'

  class << self
    def encode(user, secret, expiration: nil, scope: [])
      payload = prepare_payload(user, secret, expiration: expiration, scope: scope)
      new JWT.encode(payload, secret, ALGORITHM)
    end

    private

    def prepare_payload(user, secret, expiration: nil, scope: [])
      jti_raw = [secret, iat].join(':')
      jti = Digest::SHA256.hexdigest(jti_raw)
      payload = {
        user_id: user.id,
        iat: iat,
        jti: jti,
      }

      payload[:exp] = (Time.now.to_i + expiration) if expiration
      payload[:scope] = format_scope(scope) if scope.any?
      payload
    end

    def iat
      Time.now.to_i
    end

    # Format scope to string 'controller#action1 controller#action2'
    def format_scope(scope)
      scope.map { |sc| sc[:actions].map { |action| "#{sc[:controller]}##{action}" }.join(' ') }.join(' ')
    end
  end

  # Cryptographically verified decode. This is the only payload that may be
  # trusted for authentication or authorization.
  def decode
    return nil if token.blank?
    return nil if secret.blank?

    payload = JWT.decode(token, secret.token, true, { algorithm: ALGORITHM })
    payload.first
  rescue JWT::DecodeError
    # Includes VerificationError / IncorrectAlgorithm when the secret was
    # rotated/invalidated or the token was tampered / used an unexpected alg.
    nil
  end

  def to_s
    token
  end

  # Inspection-only decode (signature NOT verified). Used solely to read
  # user_id so the correct per-user JwtSecret can be loaded before #decode.
  # Never use this payload for identity, scope, or authorization decisions.
  def decoded_payload
    return @decoded_payload if defined?(@decoded_payload)
    @decoded_payload = JWT.decode(token, nil, false).first

    unless @decoded_payload.is_a?(Hash)
      Rails.logger.error "Invalid decoded JWT format."
      @decoded_payload = nil
    end
    @decoded_payload
  rescue JWT::DecodeError => e
    Foreman::Logging.exception('Failed to decode JWT', e)
    @decoded_payload = nil
  end

  private

  def secret
    return @secret if defined? @secret
    # user_id comes from the (unverified) payload; look up the signing secret by id.
    # Trust is established only after #decode verifies the signature with this secret.
    @secret = user_id.present? ? JwtSecret.find_by(user_id: user_id) : nil
  end

  def user_id
    @user_id ||= decoded_payload.try(:[], 'user_id')
  end
end
