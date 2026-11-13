module Foreman::Controller::CsvResponder
  extend ActiveSupport::Concern

  def csv_response(resources, columns = csv_columns, header = nil, filename = nil, classification: nil)
    filename ||= "#{controller_name}-#{Date.today}.csv"
    # F-013: machine-readable classification via HTTP headers only — do not
    # prepend rows to the CSV body (breaks automation parsers).
    level = classification || csv_output_classification

    if digital_signature_requested?
      return signed_csv_response(resources, columns, header, filename, level)
    end

    headers["Cache-Control"] = "no-cache"
    headers["Content-Type"] = "text/csv; charset=utf-8"
    headers["Content-Disposition"] = %(attachment; filename="#{filename}")
    Foreman::OutputClassification.apply_headers!(response, level)
    self.response_body = CsvExporter.export(resources, columns, header)
  end

  private

  def digital_signature_requested?
    ActiveModel::Type::Boolean.new.cast(params[:digital_signature])
  end

  # F-032: optional PKCS#7 detached signature over the exact CSV bytes.
  # Unsigned CSV streaming path remains the default (no format change).
  def signed_csv_response(resources, columns, header, filename, level)
    unless Foreman::DigitalSignature.configured?
      return render json: { error: 'digital signatures are not configured' }, status: :service_unavailable
    end

    begin
      Foreman::DigitalSignature.authorize!(User.current)
      csv_bytes = CsvExporter.export(resources, columns, header).to_a.join
      result = Foreman::DigitalSignature.sign!(
        csv_bytes,
        purpose: "csv:#{controller_name}",
        actor: User.current
      )
    rescue Foreman::DigitalSignature::Unauthorized
      return render json: { error: 'not authorized to request digital signatures' }, status: :forbidden
    rescue Foreman::DigitalSignature::InvalidCertificate, Foreman::DigitalSignature::NotConfigured,
           Foreman::DigitalSignature::Error => e
      return render json: { error: e.message }, status: :service_unavailable
    end

    payload = result.as_export(
      filename: filename,
      media_type: 'text/csv; charset=utf-8',
      classification: Foreman::OutputClassification.normalize(level)
    )
    Foreman::ExportSecurity.apply_sensitive_download_headers(response, classification: level)
    headers['X-Foreman-Digital-Signature'] = 'PKCS7-DETACHED'
    headers['X-Foreman-Signing-Cert-SHA256'] = result.certificate_fingerprint_sha256
    render json: payload, content_type: 'application/vnd.foreman.signed-export+json'
  end

  def csv_columns
    resource_class.column_names - ['created_at', 'updated_at']
  end

  def csv_output_classification
    case controller_name
    when 'hosts', 'hostgroups'
      Foreman::OutputClassification.for_kind('inventory_csv')
    when 'config_reports'
      Foreman::OutputClassification.for_kind('report_csv')
    when 'fact_values'
      Foreman::OutputClassification.for_kind('fact_csv')
    else
      Foreman::OutputClassification.for_kind('inventory_csv')
    end
  end
end
