# frozen_string_literal: true

require 'test_helper'

class DownloadFilenameSafetyTest < ActiveSupport::TestCase
  test 'template export filename uses sanitizer' do
    t = FactoryBot.build_stubbed(:provisioning_template, :name => "a/../b\nc")
    fn = t.filename
    refute_includes fn, '/'
    refute_includes fn, "\n"
    refute_includes fn, '..'
    assert_match(/\.erb\z/, fn)
  end

  test 'key pair download filename sanitizes name' do
    dangerous = Foreman::UploadSecurity.safe_download_filename("secret/../x\r\n\"y.pem", default: 'key.pem')
    refute_includes dangerous, '/'
    refute_includes dangerous, "\r"
    refute_includes dangerous, "\n"
    refute_includes dangerous, '"'
    assert dangerous.end_with?('.pem') || dangerous == 'key.pem'
  end

  test 'report filename is sanitized via UploadSecurity' do
    dangerous = "../evil\nname.txt"
    name = Foreman::UploadSecurity.safe_download_filename(dangerous, default: 'report.txt')
    refute_includes name, '..'
    refute_includes name, "\n"
    refute_includes name, '/'
  end
end
