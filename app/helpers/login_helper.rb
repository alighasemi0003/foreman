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

    # Simple math CAPTCHA: question is generated in UsersController#login and stored in session
    if captcha_enabled && session[:captcha_question]
      props[:captchaQuestion] = session[:captcha_question]
    end

    props
  end

  def mount_login
    render('common/login', props: login_props)
  end
end
