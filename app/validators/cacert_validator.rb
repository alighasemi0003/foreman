class CacertValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    return if value.blank?

    if value.bytesize > Foreman::UploadSecurity::MAX_CACERT_BYTES
      record.errors.add(attribute, _('is too large (maximum is %s bytes)') % Foreman::UploadSecurity::MAX_CACERT_BYTES)
      return
    end

    Foreman::Util.ssl_cert_store(value)
  rescue OpenSSL::X509::StoreError => e
    message = _('is not a valid CA certificate')
    Foreman::Logging.exception(message, e)
    record.errors.add(attribute, message)
  end
end
