# frozen_string_literal: true

require 'digest'
require 'securerandom'

module Foreman
  module Captcha
    # Offline accessible math challenge stored in the Rails session.
    # Answer is never sent to the browser; only the question text is.
    class Local
      SESSION_KEY = 'login_captcha'

      class << self
        # Create a new challenge, replace any previous one, return safe question.
        def issue!(session)
          a = SecureRandom.random_number(10..40)
          b = SecureRandom.random_number(10..40)
          answer = (a + b).to_s
          session[SESSION_KEY] = {
            'digest' => digest(answer),
            'created_at' => Time.now.utc.to_i,
          }
          { question: format(_('What is %<a>s + %<b>s?'), a: a, b: b) }
        end

        # Validate response. Clears the stored challenge on every attempt
        # (consume on success; force regenerate after failure / reuse).
        def verify!(response, session:)
          stored = session.delete(SESSION_KEY)
          if stored.blank?
            return Captcha::Result.new(status: :failed, message: 'captcha_missing')
          end

          created_at = stored['created_at'].to_i
          if created_at <= 0 || (Time.now.utc.to_i - created_at) > Captcha.ttl_seconds
            return Captcha::Result.new(status: :failed, message: 'captcha_expired')
          end

          expected = stored['digest'].to_s
          actual = digest(response)
          unless secure_compare(expected, actual)
            return Captcha::Result.new(status: :failed, message: 'captcha_failed')
          end

          Captcha::Result.new(status: :success, message: 'captcha_ok')
        end

        def digest(value)
          Digest::SHA256.hexdigest(value.to_s.strip)
        end

        def secure_compare(a, b)
          return false if a.blank? || b.blank? || a.bytesize != b.bytesize

          ActiveSupport::SecurityUtils.secure_compare(a, b)
        end
      end
    end
  end
end
