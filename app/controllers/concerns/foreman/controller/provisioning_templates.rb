module Foreman::Controller::ProvisioningTemplates
  extend ActiveSupport::Concern

  def load_vars_from_template
    return unless @template

    @locations        = @template.locations
    @organizations    = @template.organizations
    @template_kind_id = @template.template_kind_id
    @operatingsystems = @template.operatingsystems if @template.respond_to?(:operatingsystems)
  end

  private

  def default_template_url(template, hostgroup)
    uri      = URI.parse(Setting[:unattended_url])
    host     = uri.host
    port     = uri.port
    protocol = uri.scheme

    url_for(:only_path => false, :action => :hostgroup_template, :controller => '/unattended',
      :id => template.name, :hostgroup => hostgroup.title, :protocol => protocol,
      :host => host, :port => port)
  end

  # convert the file upload into a simple string to save in our db.
  # Bound read size so an oversized multipart body is not fully loaded.
  def handle_template_upload
    return unless params[type_name_singular] && (template = params[type_name_singular][:template])
    return unless template.respond_to?(:read) && !template.is_a?(String)

    max = Foreman::UploadSecurity::MAX_TEMPLATE_BYTES
    params[type_name_singular][:template] = template.read(max + 1)
  end

  def process_template_kind
    return unless params[type_name_singular] && (template_kind = params[type_name_singular].delete(:template_kind))
    params[type_name_singular][:template_kind_id] = template_kind[:id]
  end

  def type_name_singular
    @type_name_singular ||= resource_class.to_s.underscore
  end
end
