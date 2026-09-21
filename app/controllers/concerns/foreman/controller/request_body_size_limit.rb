# frozen_string_literal: true

module Foreman::Controller::RequestBodySizeLimit
  extend ActiveSupport::Concern

  private

  def reject_oversized_request_body(limit)
    return unless Foreman::UploadSecurity.request_body_too_large?(request, limit)

    render_error('custom_error',
      :status => :payload_too_large,
      :locals => { :message => _('Request body is too large (maximum is %s bytes)') % limit })
  end
end
