class CaptchaController < ApplicationController
  skip_before_action :require_login, :check_user_enabled, :authorize, :session_expiry, :update_activity_time, :set_taxonomy, :set_gettext_locale_db

  # Returns a new CAPTCHA key and image URL for the React login form (simple_captcha2).
  def new
    unless Setting[:captcha_enabled]
      head :not_found
      return
    end

    # simple_captcha2: generate key, create data record, return key + image URL
    key = SimpleCaptcha::Utils.generate_key(request.session_options[:id].to_s, "captcha_#{SecureRandom.hex(4)}")
    data = SimpleCaptcha::SimpleCaptchaData.get_data(key)
    data.value = generate_captcha_value
    data.save!

    # Image URL matches gem's view helper: /simple_captcha?code=KEY&time=...
    time = Time.now.to_i
    captcha_image_url = "/simple_captcha?code=#{ERB::Util.url_encode(key)}&time=#{time}"

    render json: {
      captcha_key: key,
      captcha_image_url: captcha_image_url,
    }
  end

  private

  def generate_captcha_value
    length = SimpleCaptcha.respond_to?(:length) ? SimpleCaptcha.length : 5
    length.times.map { (65 + rand(26)).chr }.join
  end
end
