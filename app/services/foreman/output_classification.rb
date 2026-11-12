# frozen_string_literal: true

# F-013: output information-classification labels for exports, printable pages,
# and third-party transfers. Complements F-019 field redaction — does not replace it.
#
# Proposed levels (not an organizationally approved standard):
#   public < internal < confidential < restricted
#
# Clients cannot lower classification via request parameters.
module Foreman
  module OutputClassification
    HEADER_ID = 'X-Foreman-Classification'
    HEADER_LABEL = 'X-Foreman-Classification-Label'
    HEADER_POLICY = 'X-Foreman-Classification-Policy'

    LEVELS = {
      'public' => {
        rank: 0,
        label: N_('Public'),
        description: N_('May be disclosed outside the organization without restriction.'),
      },
      'internal' => {
        rank: 1,
        label: N_('Internal'),
        description: N_('Organization-internal inventory and operational data.'),
      },
      'confidential' => {
        rank: 2,
        label: N_('Confidential'),
        description: N_('Host configuration, ENC, and other non-public infrastructure data.'),
      },
      'restricted' => {
        rank: 3,
        label: N_('Restricted'),
        description: N_('Secrets or highly sensitive material (keys, revealed hidden parameters).'),
      },
    }.freeze

    # Output kind => base level (raised when secrets are revealed).
    KIND_LEVELS = {
      'inventory_csv' => 'internal',
      'report_csv' => 'internal',
      'fact_csv' => 'internal',
      'host_enc' => 'confidential',
      'host_yaml' => 'confidential',
      'inherited_parameters' => 'confidential',
      'template_export' => 'internal',
      'report_template_output' => 'internal',
      'key_pair_pem' => 'restricted',
      'ui_html' => 'internal',
    }.freeze

    POLICY_ID = 'foreman-proposed-v1'

    module_function

    def enabled?
      Setting[:output_classification_enabled] != false
    rescue StandardError
      true
    end

    def normalize(level)
      key = level.to_s.downcase.strip
      return 'internal' unless LEVELS.key?(key)

      key
    end

    def label_for(level)
      meta = LEVELS[normalize(level)]
      _(meta[:label])
    end

    def rank(level)
      LEVELS[normalize(level)][:rank]
    end

    def highest(*levels)
      levels.map { |l| normalize(l) }.max_by { |l| rank(l) }
    end

    # Server-side classification for a known output kind.
    # +secrets_revealed+ raises confidential → restricted for ENC/YAML-style exports.
    # Request parameters are ignored — callers must not pass client-supplied levels.
    def for_kind(kind, secrets_revealed: false)
      base = KIND_LEVELS[kind.to_s] || 'internal'
      return 'restricted' if secrets_revealed && %w[host_enc host_yaml inherited_parameters].include?(kind.to_s)

      base
    end

    def apply_headers!(response, level)
      return response unless enabled?
      return response unless response

      level = normalize(level)
      response.headers[HEADER_ID] = level
      response.headers[HEADER_LABEL] = label_for(level)
      response.headers[HEADER_POLICY] = POLICY_ID
      response
    end

    # Visible YAML comment preamble (does not alter the document structure).
    def yaml_preamble(level)
      level = normalize(level)
      [
        "# #{HEADER_ID}: #{level}",
        "# #{HEADER_LABEL}: #{label_for(level)}",
        "# #{HEADER_POLICY}: #{POLICY_ID}",
        "# Classification: #{label_for(level)} — #{_(LEVELS[level][:description])}",
        '',
      ].join("\n")
    end

    def labeled_yaml(object, level)
      yaml_preamble(level) + object.to_yaml
    end

    # Human-visible print/HTML banner text (no secrets).
    def print_banner_text(level)
      level = normalize(level)
      _("Classification: %{label}") % { label: label_for(level) }
    end

    def inventory
      LEVELS.map do |id, meta|
        {
          id: id,
          label: _(meta[:label]),
          description: _(meta[:description]),
          rank: meta[:rank],
        }
      end
    end
  end
end
