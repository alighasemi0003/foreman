# frozen_string_literal: true

module OutputClassificationHelper
  # Controllers may set @output_classification; clients cannot lower it via params.
  def output_classification_level
    explicit = @output_classification.presence
    return Foreman::OutputClassification.normalize(explicit) if explicit

    Foreman::OutputClassification.for_kind('ui_html')
  end

  def output_classification_print_label
    Foreman::OutputClassification.print_banner_text(output_classification_level)
  end

  def show_output_classification_print_banner?
    return false unless User.current
    return false unless Foreman::OutputClassification.enabled?

    true
  end
end
