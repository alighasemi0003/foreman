# frozen_string_literal: true

# F-026: shared HTTP/API rate limiting via Rails.cache (Redis in multi-worker deploys).
#
# Client identity is request.remote_ip only (ActionDispatch::RemoteIp / trusted_proxies).
# Never keys on usernames, passwords, or raw Authorization / PAT values.
module Foreman
  class HttpRateLimit
    CACHE_PREFIX = 'foreman:http_rl'
    CATEGORIES = %i[login captcha api graphql unattended general].freeze

    Result = Struct.new(:allowed, :category, :count, :limit, :retry_after, :error, keyword_init: true)

    class << self
      def enabled?
        Setting[:http_rate_limit_enabled]
      rescue StandardError
        true
      end

      def fail_closed?
        Setting[:http_rate_limit_fail_closed]
      rescue StandardError
        false
      end

      def period_seconds
        [[Setting[:http_rate_limit_period].to_i, 10].max, 3600].min
      rescue StandardError
        60
      end

      def limit_for(category)
        key = setting_key_for(category)
        value = Setting[key].to_i
        value = default_limit_for(category) if value <= 0
        [[value, 1].max, 100_000].min
      rescue StandardError
        default_limit_for(category)
      end

      def default_limit_for(category)
        case category.to_sym
        when :login then 20
        when :captcha then 30
        when :graphql then 60
        when :unattended then 180
        when :api then 300
        else 600
        end
      end

      def setting_key_for(category)
        case category.to_sym
        when :login then :http_rate_limit_login
        when :captcha then :http_rate_limit_captcha
        when :graphql then :http_rate_limit_graphql
        when :unattended then :http_rate_limit_unattended
        when :api then :http_rate_limit_api
        else :http_rate_limit_general
        end
      end

      # Classify a Rack path + method into a policy bucket.
      def classify(path, request_method)
        path = path.to_s
        method = request_method.to_s.upcase

        return :exempt if exempt_path?(path)

        if path.match?(%r{\A/(users/login|users/extlogin|users/reauthenticate)(/|\z)}i) &&
            %w[POST PUT PATCH].include?(method)
          return :login
        end
        return :captcha if path.match?(%r{\A/users/captcha_challenge(/|\z)}i)
        return :graphql if path.match?(%r{\A/api(/v2)?/graphql(/|\z)}i)
        return :unattended if path.match?(%r{\A/(unattended|userdata)(/|\z)}i)
        return :api if path.start_with?('/api')

        :general
      end

      def exempt_path?(path)
        path.match?(%r{\A/(assets|webpack|packs|favicon\.ico|images)(/|\z)}i) ||
          path.match?(%r{\A/(api(/v2)?/)?(ping|statuses)(/|\z)}i) ||
          path == '/status' ||
          path.start_with?('/rails/')
      end

      # Increment the shared counter. Returns a Result.
      def check!(category:, client_ip:)
        return Result.new(allowed: true, category: category, count: 0, limit: 0, retry_after: 0) if category == :exempt
        return Result.new(allowed: true, category: category, count: 0, limit: 0, retry_after: 0) unless enabled?

        ip = normalize_ip(client_ip)
        return Result.new(allowed: true, category: category, count: 0, limit: 0, retry_after: 0) if ip.blank?

        period = period_seconds
        limit = limit_for(category)
        bucket = Time.now.to_i / period
        cache_key = "#{CACHE_PREFIX}:#{category}:#{ip}:#{bucket}"
        ttl = period + 5

        count = Rails.cache.increment(cache_key, 1, expires_in: ttl, initial: 0)
        # Some stores return nil when the key was missing and initial is unsupported.
        if count.nil?
          Rails.cache.write(cache_key, 1, expires_in: ttl, unless_exist: true)
          count = Rails.cache.read(cache_key).to_i
          count = 1 if count <= 0
        end

        remaining_ttl = ((bucket + 1) * period) - Time.now.to_i
        retry_after = [remaining_ttl, 1].max

        if count > limit
          Result.new(allowed: false, category: category, count: count, limit: limit, retry_after: retry_after)
        else
          Result.new(allowed: true, category: category, count: count, limit: limit, retry_after: retry_after)
        end
      rescue StandardError => e
        handle_store_failure(e, category)
      end

      def normalize_ip(ip)
        return if ip.blank?
        IPAddr.new(ip.to_s).to_s
      rescue IPAddr::InvalidAddressError
        ip.to_s.gsub(/[^\w\-.:]/, '').truncate(64).presence
      end

      private

      def handle_store_failure(error, category)
        Foreman::Logging.exception('HTTP rate limit cache unavailable', error, :logger => 'app')
        if fail_closed?
          Result.new(allowed: false, category: category, count: 0, limit: 0, retry_after: period_seconds,
                     error: :store_unavailable)
        else
          Foreman::SecurityEvent.log(
            event: 'HTTP_RATE_LIMIT_FAIL_OPEN',
            status: 'DEGRADED',
            level: :warn,
            details: "category=#{category} error=#{error.class}"
          )
          Result.new(allowed: true, category: category, count: 0, limit: 0, retry_after: 0, error: :store_unavailable)
        end
      end
    end
  end
end
