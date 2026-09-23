# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Foreman
  module Captcha
    # Cloudflare Turnstile siteverify client.
    # Verification URL is fixed (not user-controlled) to avoid SSRF.
    class TurnstileVerifier
      CONNECT_TIMEOUT = 3
      READ_TIMEOUT = 5

      def verify(response_token, remote_ip: nil)
        body = post_siteverify(response_token, remote_ip)
        parse_response(body)
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNREFUSED, Errno::EHOSTUNREACH,
             Errno::ETIMEDOUT, SocketError, OpenSSL::SSL::SSLError => e
        Rails.logger.warn("[Captcha] Turnstile provider network error: #{e.class}")
        Captcha::Result.new(status: :provider_error, message: 'captcha_provider_error')
      rescue JSON::ParserError
        Rails.logger.warn('[Captcha] Turnstile returned malformed JSON')
        Captcha::Result.new(status: :provider_error, message: 'captcha_provider_error')
      rescue StandardError => e
        Rails.logger.warn("[Captcha] Turnstile unexpected error: #{e.class}")
        Captcha::Result.new(status: :provider_error, message: 'captcha_provider_error')
      end

      private

      def post_siteverify(response_token, remote_ip)
        uri = URI.parse(Captcha::TURNSTILE_SITEVERIFY_URL)
        form = {
          'secret' => Captcha.secret_key,
          'response' => response_token,
        }
        form['remoteip'] = remote_ip.to_s if remote_ip.present?

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = CONNECT_TIMEOUT
        http.read_timeout = READ_TIMEOUT

        request = Net::HTTP::Post.new(uri.request_uri)
        request.set_form_data(form)
        response = http.request(request)

        unless response.is_a?(Net::HTTPSuccess)
          Rails.logger.warn("[Captcha] Turnstile HTTP status=#{response.code}")
          raise ProviderHttpError, "status=#{response.code}"
        end

        response.body.to_s
      end

      def parse_response(body)
        data = JSON.parse(body)
        if data['success'] == true
          return Captcha::Result.new(status: :success, message: 'captcha_ok')
        end

        codes = Array(data['error-codes']).map(&:to_s)
        Rails.logger.warn("[Captcha] Turnstile verification failed codes=#{codes.join(',')}")
        Captcha::Result.new(status: :failed, message: 'captcha_failed', error_codes: codes)
      end

      class ProviderHttpError < StandardError; end
    end
  end
end
