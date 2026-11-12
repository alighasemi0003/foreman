# frozen_string_literal: true

# F-019: classify and redact sensitive fields at general-purpose export boundaries.
#
# Operational paths (provisioning templates, Host#info consumers) keep raw values.
# Human/API ENC and inventory-style exports redact hidden parameters unless the
# caller is explicitly authorized (edit_params).
module Foreman
  module ExportSecurity
    module_function

    # Returns a deep copy of +info+ (Host#info shape) with hidden host-parameter
    # values replaced by HiddenValue::HIDDEN_VALUE. Static ENC keys (root_pw,
    # interfaces, taxonomy, …) are left intact; BMC passwords remain gated by
    # Setting[:bmc_credentials_accessible] inside Nic::BMC#password / to_export.
    def redact_host_info(info, host)
      result = info.deep_dup
      parameters = result['parameters']
      return result unless parameters.is_a?(Hash)

      host.host_params_hash.each do |name, meta|
        next unless meta[:hidden_value?]
        next unless parameters.key?(name)

        parameters[name] = HiddenValue::HIDDEN_VALUE
      end
      result
    end

    # Serialize inherited Parameter records for API export without leaking
    # hidden values unless +reveal_hidden+ is true.
    def serialize_parameters_for_export(parameters, reveal_hidden: false)
      Array(parameters).map do |param|
        value = if reveal_hidden && param.editable_by_user?
                  param.value
                else
                  param.safe_value
                end
        {
          'id' => param.id,
          'name' => param.name,
          'value' => value,
          'parameter_type' => param.parameter_type,
          'priority' => param.priority,
          'hidden_value?' => param.hidden_value?,
          'associated_type' => param.associated_type,
          'associated_label' => (param.associated_type != 'global') ? param.try(:associated_label) : nil,
        }.compact
      end
    end

    def apply_sensitive_download_headers(response, classification: nil)
      response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate'
      response.headers['Pragma'] = 'no-cache'
      response.headers['Expires'] = '0'
      if classification
        Foreman::OutputClassification.apply_headers!(response, classification)
      end
      response
    end
  end
end
