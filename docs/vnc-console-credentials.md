# VNC console credentials (F-025 / Control 58)

## Credential flow (secured)

1. Authorized user opens Host / Compute Resource VM **Console**
   (`console_hosts` or `console_compute_resources_vms`), subject to
   permission checks and optional reauthentication.
2. Provider `console(uuid)` (Libvirt / VMware VNC path) generates a **new**
   random display password (`random_password`, 8 chars for VNC) and writes it
   to the hypervisor display (`update_display` / `config_vnc`).
3. `WsProxy.start` with `rfb_auth: true` creates a short-lived
   `Foreman::Console::Ticket` (opaque id + mode-0600 server-side file holding
   the display password, VNC target, binding, expiry) and starts
   `script/foreman-vnc-gateway` on a port in `5910..5930`.
4. HTML (`hosts/console/vnc.html.erb`) receives **host/port/path** only.
   `path` is `/?ticket=<id>`. The hypervisor VNC password is **not** rendered.
5. Browser noVNC connects to `ws(s)://…/?ticket=…` with **no** RFB password.
6. The gateway validates the ticket (match, not expired, single-use), consumes
   it, authenticates to the hypervisor with the server-held password
   (`RfbAuthProxy` + VNC DES), then offers RFB security type **None** to the
   browser and splices the session.

OpenStack uses a different console body (not this HTML password path).
VMware VMRC uses a clone ticket URL, not noVNC.
Libvirt **SPICE** still uses websockify + embedded session password (out of
scope for Control 58 VNC).

## Authorization properties

| Property | Behavior |
| --- | --- |
| Foreman UI authz | Required before ticket issuance |
| Ticket entropy | `SecureRandom.urlsafe_base64(32)` |
| Binding | Provider-scoped (`libvirt:<uuid>` / `vmware:<id>`) |
| TTL | Matches proxy timeout (default 120s) |
| Single-use | `consume!` clears stored password after first WS authorize |
| Cross-host | Ticket maps to one VNC target; wrong ticket → HTTP 403 |
| Logs | Gateway/WsProxy must not log password or ticket secret material |

## Why this satisfies Control 58

Websockify alone is a byte tunnel; RFB auth would remain browser-visible.
The RFB-terminating gateway keeps the reusable (per-open) display password
server-side. Moving `data-password` to an XHR would **not** be sufficient.

## Mitigations retained

- `Cache-Control: private, no-store` on console HTML
- Optional reauthentication before opening a console
