module Foreman::Controller::ConsoleCommon
  def console
    # Console pages may embed short-lived display credentials for noVNC/SPICE.
    # Never allow shared/proxy caches to store them.
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

