module LoginHelper
  def login_props
    captcha_enabled = Setting[:captcha_enabled]

    props = {
      token: form_authenticity_token,
      caption: Setting.replace_keywords(Setting[:login_text]),
      alerts: flash_inline,
      logoSrc: image_path("login_logo.png"),
      captchaEnabled: captcha_enabled,
    }

    # simple_captcha2: React fetches a new captcha from this URL (returns captcha_key + captcha_image_url)
    if captcha_enabled
      props[:captchaNewUrl] = captcha_new_path
    end

    props
  end

  def mount_login
    render('common/login', props: login_props)
  end
end
