module Foreman::Controller::ConsoleCommon
  def console
    # VNC (Libvirt/VMware) uses a short-lived ticket + server-side RFB auth proxy;
    # the hypervisor display password must not be cacheable if ever present.
    # SPICE may still embed a session password — keep no-store either way.
    response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    render case @console[:type]
             when 'spice'
               'hosts/console/spice'
             when 'vnc'
               'hosts/console/vnc'
             when 'vmrc'
               'hosts/console/vmrc'
             else
               'hosts/console/log'
           end
  end
end

