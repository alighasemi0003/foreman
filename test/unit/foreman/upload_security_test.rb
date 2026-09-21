# frozen_string_literal: true

require 'test_helper'

class Foreman::UploadSecurityTest < ActiveSupport::TestCase
  # Minimal JPEG: SOI + APP0 stub + EOI (signature validation only).
  def minimal_jpeg(padding: 0)
    ("\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00".b +
      ("\x00".b * [padding, 16].max) +
      "\xFF\xD9".b)
  end

  test 'valid_jpeg_avatar? accepts JPEG within size limits' do
    assert Foreman::UploadSecurity.valid_jpeg_avatar?(minimal_jpeg)
  end

  test 'valid_jpeg_avatar? rejects zero-byte and tiny payloads' do
    refute Foreman::UploadSecurity.valid_jpeg_avatar?(''.b)
    refute Foreman::UploadSecurity.valid_jpeg_avatar?("\xFF\xD8\xFF\xD9".b)
  end

  test 'valid_jpeg_avatar? rejects oversized JPEG' do
    huge = minimal_jpeg(padding: Foreman::UploadSecurity::MAX_AVATAR_BYTES)
    refute Foreman::UploadSecurity.valid_jpeg_avatar?(huge)
  end

  test 'valid_jpeg_avatar? rejects HTML SVG PNG GIF PDF and executables' do
    refute Foreman::UploadSecurity.valid_jpeg_avatar?('<html><body>x</body></html>'.b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?('<svg xmlns="http://www.w3.org/2000/svg"></svg>'.b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?("\x89PNG\r\n\x1A\n".b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?('GIF89a'.b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?('%PDF-1.4'.b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?("MZ".b + ('x'.b * 40))
    refute Foreman::UploadSecurity.valid_jpeg_avatar?("\x7FELF".b + ('x'.b * 40))
  end

  test 'valid_jpeg_avatar? rejects truncated JPEG without EOI' do
    truncated = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00".b + ("\x00".b * 40)
    refute Foreman::UploadSecurity.valid_jpeg_avatar?(truncated)
  end

  test 'extract_avatar_binary decodes base64 JPEG' do
    jpeg = minimal_jpeg
    binary = Foreman::UploadSecurity.extract_avatar_binary(Base64.strict_encode64(jpeg))
    assert_equal jpeg, binary
  end

  test 'extract_avatar_binary rejects invalid base64 content' do
    assert_nil Foreman::UploadSecurity.extract_avatar_binary(Base64.strict_encode64('<html>not an image</html>' + ('x' * 40)))
  end

  test 'safe_download_filename strips path and control characters' do
    assert_equal 'name.erb', Foreman::UploadSecurity.safe_download_filename('../name.erb')
    assert_equal 'name.erb', Foreman::UploadSecurity.safe_download_filename('..\\name.erb')
    assert_equal 'a_b.erb', Foreman::UploadSecurity.safe_download_filename("a\rb.erb")
    assert_equal 'a_b.erb', Foreman::UploadSecurity.safe_download_filename("a\nb.erb")
    assert_equal 'a_b.erb', Foreman::UploadSecurity.safe_download_filename('a"b.erb')
  end

  test 'safe_download_filename preserves unicode and enforces length' do
    assert_equal 'گزارش.erb', Foreman::UploadSecurity.safe_download_filename('گزارش.erb')
    long = ('a' * 300) + '.erb'
    result = Foreman::UploadSecurity.safe_download_filename(long)
    assert result.bytesize <= Foreman::UploadSecurity::MAX_DOWNLOAD_FILENAME_LENGTH
    assert result.end_with?('.erb')
  end

  test 'safe_download_filename falls back for empty or dots' do
    assert_equal 'download', Foreman::UploadSecurity.safe_download_filename('')
    assert_equal 'download', Foreman::UploadSecurity.safe_download_filename('...')
    assert_equal 'download', Foreman::UploadSecurity.safe_download_filename('/')
  end

  test 'request_body_too_large? uses content_length' do
    request = mock('request')
    request.stubs(:content_length).returns(Foreman::UploadSecurity::MAX_FACTS_BODY_BYTES + 1)
    request.stubs(:respond_to?).with(:raw_post).returns(false)
    assert Foreman::UploadSecurity.request_body_too_large?(request, Foreman::UploadSecurity::MAX_FACTS_BODY_BYTES)

    request.stubs(:content_length).returns(100)
    refute Foreman::UploadSecurity.request_body_too_large?(request, Foreman::UploadSecurity::MAX_FACTS_BODY_BYTES)
  end
end
