# frozen_string_literal: true

::SecureHeaders::Configuration.default do |config|
  if SETTINGS[:hsts_enabled]
    config.hsts = "max-age=#{20.years.to_i}; includeSubDomains"
  else
    # Expire previously cached HSTS when explicitly disabled.
    config.hsts = "max-age=0; includeSubDomains"
  end

  # Clickjacking / MIME / referrer baselines (secure_headers defaults x_* when nil,
  # but referrer_policy defaults to OPT_OUT — set explicitly).
  config.x_frame_options = "SAMEORIGIN"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "0" # deprecated browser feature; CSP is primary XSS control
  config.referrer_policy = "strict-origin-when-cross-origin"

  # Production HTTPS deployments should not allow plaintext WebSocket endpoints.
  connect_src = ["'self'", "wss:"]
  connect_src << "ws:" unless SETTINGS[:require_ssl]

  script_src = ["'unsafe-eval'", "'unsafe-inline'", "'self'"]
  frame_src = ["'self'"]
  child_src = ["'self'"]

  # Cloudflare Turnstile challenge widget (login CAPTCHA only when enabled).
  # Single fixed origin — no wildcards. Disabled CAPTCHA keeps CSP unchanged.
  if SETTINGS.dig(:captcha, :enabled)
    turnstile = 'https://challenges.cloudflare.com'
    script_src << turnstile
    frame_src << turnstile
    child_src << turnstile
    connect_src << turnstile
  end

  # Enforcing CSP. 'unsafe-inline' / 'unsafe-eval' remain for legacy ERB + webpack/React
  # until nonce/hash migration; tracked as Remaining Risk (not removed here).
  config.csp = {
    :default_src => ["'self'"],
    :base_uri => ["'self'"],
    :object_src => ["'none'"],
    :frame_ancestors => ["'self'"],
    :form_action => ["'self'"],
    :frame_src => frame_src,
    :child_src => child_src,
    :connect_src => connect_src,
    :font_src => ["'self'", "data:"],
    :img_src => ["'self'", "data:"],
    :style_src => ["'unsafe-inline'", "'self'"],
    :script_src => script_src,
  }
end

# Permissions-Policy is not provided by secure_headers 7.x — set via Rails defaults.
Rails.application.config.action_dispatch.default_headers ||= {}
Rails.application.config.action_dispatch.default_headers["Permissions-Policy"] =
  "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
