require 'ipaddr'

class UserdataController < ApplicationController
  include ::Foreman::Controller::TemplateRendering

  layout false

  # Cloud-init / nocloud-net bootstrap endpoints: no interactive login or CSRF.
  # Authorization is host-scoped via provisioning token and/or request IP binding
  # (see #authorize_found_host). MAC alone is not sufficient.
  skip_before_action :require_login, :check_user_enabled, :session_expiry, :update_activity_time, :set_taxonomy, :authorize, :verify_authenticity_token

  before_action :set_admin_user
  before_action :skip_secure_headers
  before_action :skip_session
  before_action :find_host

  def userdata
    render_userdata_template
  end

  def metadata
    data = {
      :'instance-id' => "i-#{Digest::SHA1.hexdigest(@host.id.to_s)[0..17]}",
      :hostname => @host.name,
      :mac => @host.mac,
      :'local-ipv4' => @host.ip,
      :'local-hostname' => @host.name,
    }
    render plain: data.map { |key, value| "#{key}: #{value}" }.join("\n")
  end

  private

  def render_userdata_template
    template = @host.provisioning_template(kind: 'cloud-init')
    template ||= @host.provisioning_template(kind: 'user_data')
    unless template
      render_error(
        _('Unable to find user-data or cloud-init template for host %{host} running %{os}'),
        :status => :not_found,
        :host => @host.name,
        :os => @host.operatingsystem
      )
      return
    end
    safe_render(template)
  end

  def skip_secure_headers
    SecureHeaders.opt_out_of_all_protection(request)
  end

  def skip_session
    request.session_options[:skip] = true
  end

  def find_host
    # Do not accept spoof/hostname query params here: those are preview paths for
    # authenticated UnattendedController users, not for anonymous userdata clients.
    query_params = {
      ip: request.remote_ip,
      token: params[:token],
    }
    query_params[:mac_list] = Foreman::UnattendedInstallation::MacListExtractor.new.extract_from_env(request.env, params: params)

    host_finder = Foreman::UnattendedInstallation::HostFinder.new(query_params: query_params)
    @host = host_finder.search
    @host_search_paths = host_finder.search_paths

    unless @host
      render_error(_('Could not find host for request %{request_ip}'),
        :status => :not_found,
        :request_ip => request.remote_ip
      )
      return false
    end

    authorize_found_host
  end

  # Trust model:
  # 1) Valid (non-expired) host provisioning token in params[:token] — host-scoped secret
  # 2) Discovery by request IP alone — client must appear as that host's address
  # 3) Discovery by MAC (URL path / RHN headers) — also require request IP to belong to that host
  def authorize_found_host
    paths = Array(@host_search_paths)

    return true if paths.any? { |path| path.start_with?('token:') }
    return true if paths.any? { |path| path.start_with?('ip:') }
    return true if request_ip_belongs_to_host?

    # Same client-facing message as unknown host to avoid confirming MAC existence.
    render_error(_('Could not find host for request %{request_ip}'),
      :status => :not_found,
      :request_ip => request.remote_ip
    )
    false
  end

  def request_ip_belongs_to_host?
    addr = normalize_request_ip(request.remote_ip)
    return false if addr.blank?

    @host.interfaces.any? do |nic|
      [nic.ip, nic.ip6].compact.any? { |ip| normalize_request_ip(ip) == addr }
    end
  end

  def normalize_request_ip(value)
    IPAddr.new(value.to_s.split(',').first.strip).native.to_s
  rescue IPAddr::InvalidAddressError, ArgumentError
    value.to_s.split(',').first.to_s.strip.presence
  end
end
