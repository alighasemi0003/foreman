# frozen_string_literal: true

# Shared policy for exporting Host#info (ENC / YAML) and inherited parameters.
module Foreman::Controller::HostInfoExport
  extend ActiveSupport::Concern

  private

  # Authorized sensitive ENC export: edit_params.
  # Optional show_hidden_parameters=false forces redaction even for editors.
  # show_hidden_parameters=true without edit_params cannot bypass redaction.
  def reveal_hidden_host_info_secrets?
    return false unless User.current&.can?(:edit_params)
    if params.key?(:show_hidden_parameters)
      return Foreman::Cast.to_bool(params[:show_hidden_parameters]) == true
    end
    true
  end

  # Matches Parameters API: require flag + edit_params.
  def reveal_hidden_parameters_for_api?
    Foreman::Cast.to_bool(params[:show_hidden_parameters]) == true &&
      User.current&.can?(:edit_params)
  end

  def host_info_for_export(host = @host)
    info = host.info
    reveal = reveal_hidden_host_info_secrets?
    payload = reveal ? info : Foreman::ExportSecurity.redact_host_info(info, host)
    log_host_info_export(host, reveal: reveal)
    payload
  end

  def log_host_info_export(host, reveal:)
    Foreman::SecurityEvent.log(
      event: 'HOST_INFO_EXPORT',
      status: reveal ? 'SUCCESS_FULL' : 'SUCCESS_REDACTED',
      actor: User.current&.login,
      target: host.to_label,
      details: "hidden_params=#{reveal ? 'revealed' : 'redacted'}"
    )
  end
end
