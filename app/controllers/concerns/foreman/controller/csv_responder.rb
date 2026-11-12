module Foreman::Controller::CsvResponder
  extend ActiveSupport::Concern

  def csv_response(resources, columns = csv_columns, header = nil, filename = nil, classification: nil)
    filename ||= "#{controller_name}-#{Date.today}.csv"
    headers["Cache-Control"] = "no-cache"
    headers["Content-Type"] = "text/csv; charset=utf-8"
    headers["Content-Disposition"] = %(attachment; filename="#{filename}")
    # F-013: machine-readable classification via HTTP headers only — do not
    # prepend rows to the CSV body (breaks automation parsers).
    level = classification || csv_output_classification
    Foreman::OutputClassification.apply_headers!(response, level)
    self.response_body = CsvExporter.export(resources, columns, header)
  end

  private

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
