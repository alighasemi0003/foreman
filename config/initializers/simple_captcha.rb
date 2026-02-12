# simple_captcha2 configuration (ImageMagick 'convert' must be on PATH or image_magick_path)
SimpleCaptcha.setup do |sc|
  sc.image_magick_path = '/usr/bin'
  sc.image_size = '120x40'
  sc.image_style = 'simple_black'
end

# In test environment, captcha always passes
SimpleCaptcha.always_pass = Rails.env.test?