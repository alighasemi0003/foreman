class KeyPairsController < ApplicationController
  include Foreman::Controller::ComputeResourcesCommon

  before_action :find_compute_resource
  before_action :find_resource, :only => [:show, :export]

  def index
    @key_pairs = @compute_resource.get_compute_key_pairs
  rescue => e
    compute_resource_error("SSH keys", e)
  end

  # Compatibility download: plaintext PEM for SSH / automation after reauth.
  def show
    return unless ensure_reauthenticated!('key_pairs.download')

    # Never accept a passphrase on GET/query — it would leak into logs and history.
    if params[:passphrase].present? || params[:export_passphrase].present?
      return deny_key_export(_('Passphrase-protected export requires POST to the encrypted export endpoint.'),
        status: :bad_request)
    end

    send_key_download(@key_pair.export_secret, encrypted: false)
  end

  # Passphrase-protected PEM export (encrypted PKCS#1 / OpenSSL traditional).
  # Passphrase must be in the POST body (never query string) and is parameter-filtered.
  def export
    return unless ensure_reauthenticated!('key_pairs.download')

    passphrase = params[:passphrase].presence || params[:export_passphrase].presence
    if passphrase.blank?
      return deny_key_export(_('A passphrase is required for encrypted private-key export.'),
        status: :unprocessable_entity)
    end

    begin
      payload = @key_pair.export_secret(passphrase: passphrase)
    rescue Foreman::Exception => e
      return deny_key_export(e.message, status: :unprocessable_entity)
    end

    send_key_download(payload, encrypted: true)
  end

  def create
    return unless ensure_reauthenticated!('key_pairs.recreate')

    if @compute_resource.recreate
      process_success :success_msg => _('Successfully recreated'),
        :success_redirect => compute_resource_path(@compute_resource)
    else
      process_error :error_msg => _('Could not recreate a new SSH key')
    end
  end

  def destroy
    return unless ensure_reauthenticated!('key_pairs.destroy')

    key_to_delete = params[:id]
    return not_found unless key_to_delete
    if @compute_resource.delete_key_from_resource(key_to_delete)
      process_success :success_msg => _('Successfully delete %s') % key_to_delete,
        :success_redirect => compute_resource_path(@compute_resource)
    else
      process_error :error_msg => _('Could not delete %s') % key_to_delete
    end
  end

  private

  def deny_key_export(message, status:)
    render plain: message, status: status, content_type: 'text/plain'
  end

  def send_key_download(payload, encrypted:)
    @key_pair.update(audit_comment: _("%{user} Downloaded %{key} as %{format} file") % {
      user: User.current.name,
      key: @key_pair.name,
      format: encrypted ? 'encrypted pem' : 'pem',
    })
    filename = Foreman::UploadSecurity.safe_download_filename("#{@key_pair.name}.pem", default: 'key.pem')
    response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    send_data payload, :filename => filename, :disposition => 'attachment', :type => 'application/x-pem-file'
  end

  def find_compute_resource
    # Key download must be scoped to compute resources the user can view — not a global find.
    @compute_resource = ComputeResource.authorized(:view_compute_resources).find(params[:compute_resource_id])
    return not_found unless @compute_resource.capabilities.include?(:key_pair)
    @compute_resource
  rescue ActiveRecord::RecordNotFound
    not_found
  end

  def find_resource
    @key_pair = @compute_resource.key_pair
    return not_found unless @key_pair && @key_pair.id.to_s == params[:id].to_s
  end

  def action_permission
    case params[:action]
      when 'show', 'export'
        :view
      when 'create'
        :destroy
      else
        super
    end
  end

  def controller_permission
    'keypairs'
  end
end
