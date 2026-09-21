# frozen_string_literal: true

require 'test_helper'

class HttpProxyCacertValidationTest < ActiveSupport::TestCase
  let(:valid_pem) { File.read(Rails.root.join('test/static_fixtures/certificates/example.com.crt')) }
  let(:valid_pem2) { File.read(Rails.root.join('test/static_fixtures/certificates/example2.com.crt')) }

  test 'accepts valid CA certificate' do
    proxy = HttpProxy.new(:name => 'with-ca', :url => 'http://proxy.example:3128', :cacert => valid_pem)
    assert proxy.valid?, proxy.errors.full_messages.to_sentence
  end

  test 'accepts CA certificate bundle' do
    proxy = HttpProxy.new(:name => 'bundle', :url => 'http://proxy.example:3128', :cacert => valid_pem + "\n" + valid_pem2)
    assert proxy.valid?, proxy.errors.full_messages.to_sentence
  end

  test 'rejects malformed PEM' do
    proxy = HttpProxy.new(:name => 'bad', :url => 'http://proxy.example:3128',
      :cacert => "-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n")
    refute proxy.valid?
    assert proxy.errors[:cacert].present?
  end

  test 'rejects arbitrary text' do
    proxy = HttpProxy.new(:name => 'text', :url => 'http://proxy.example:3128', :cacert => 'just some text')
    refute proxy.valid?
    assert proxy.errors[:cacert].present?
  end

  test 'rejects oversized cacert' do
    huge = valid_pem + ('B' * (Foreman::UploadSecurity::MAX_CACERT_BYTES + 1))
    proxy = HttpProxy.new(:name => 'huge', :url => 'http://proxy.example:3128', :cacert => huge)
    refute proxy.valid?
    assert proxy.errors[:cacert].any? { |m| m.include?('too large') || m.include?('valid') }
  end

  test 'blank cacert remains optional' do
    proxy = HttpProxy.new(:name => 'none', :url => 'http://proxy.example:3128', :cacert => '')
    assert proxy.valid?, proxy.errors.full_messages.to_sentence
  end
end
