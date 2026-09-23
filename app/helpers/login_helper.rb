module LoginHelper
  def login_props
    {
      token: form_authenticity_token,
      caption: Setting.replace_keywords(Setting[:login_text]),
      alerts: flash_inline,
      logoSrc: image_path("login_logo.png"),
      # Only enabled/provider/siteKey — never Turnstile secret.
      captcha: Foreman::Captcha.frontend_config,
    }
  end

  def mount_login
    render('common/login', props: login_props)
  end
end
