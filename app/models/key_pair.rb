require 'openssl'

class KeyPair < ApplicationRecord
  include Encryptable

  audited :except => :secret, :associated_with => :compute_resource
  belongs_to :compute_resource
  validates_lengths_from_database
  validates :name, :secret, :presence => true
  validates :compute_resource_id, :presence => true, :uniqueness => true

  encrypts :secret

  def skip_strip_attrs
    ['secret']
  end

  # Returns PEM material for download.
  # With a passphrase, returns traditional OpenSSL encrypted PEM (Proc-Type: 4,ENCRYPTED).
  # Without a passphrase, returns the recoverable private key (SSH / Fog compatible).
  def export_secret(passphrase: nil)
    material = secret
    return material if passphrase.blank?

    pkey = OpenSSL::PKey.read(material)
    pkey.export(OpenSSL::Cipher.new('aes-256-cbc'), passphrase)
  rescue OpenSSL::PKey::PKeyError, ArgumentError, TypeError
    raise Foreman::Exception.new(N_("Private key cannot be exported in encrypted PEM form"))
  end
end
