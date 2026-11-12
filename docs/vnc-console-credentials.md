# VNC console credentials (F-025 / Control 58)

## Credential flow

1. Authorized user opens Host / Compute Resource VM **Console**
   (`console_hosts` or `console_compute_resources_vms`).
2. Provider `console(uuid)` (Libvirt / VMware VNC path) generates a **new**
   random display password (`random_password`, 8 chars for VNC) and writes it
   to the hypervisor display (`update_display` / `config_vnc`).
3. `WsProxy.start` launches **websockify** as a raw TCP tunnel from a local
   port in `5910..5930` to `hypervisor:vnc_port`. The password is **not**
   consumed by websockify; it is returned for the HTML console page.
4. `hosts/console/vnc.html.erb` embeds connection parameters, including
   `data-password`, for `bundle_novnc.js`.
5. Browser noVNC (`RFB`) connects to `ws(s)://…` and performs **RFB security
   handshake** using that password (`options.credentials.password`).

OpenStack uses a different console body (not this HTML password path).
VMware VMRC uses a clone ticket URL, not noVNC password embedding.

## What the audit observed

`data-password` in the DOM / JS is real. Any script with access to the
console page can read the session VNC password.

## Authorization boundary today

- Foreman UI/API authorization gates who may **open** the console page.
- Websockify itself does **not** validate the Foreman session; reachability
  of the proxy port + RFB password protect the tunnel.
- The password is **per console open** (regenerated), not the compute-resource
  API password stored in Foreman. It remains valid on the VM until the next
  console password update.

## Why the browser still needs the password

Websockify is a byte tunnel. RFB authentication is end-to-end between noVNC
and the hypervisor VNC server. Without an RFB-terminating proxy, the browser
**must** know the VNC password. Moving it from `data-password` to an XHR
still delivers the same reusable session secret to JavaScript and does **not**
satisfy Control 58.

## Server-side credential handling: feasibility

| Approach | Feasible in-tree now? | Notes |
| --- | --- | --- |
| Remove password from DOM only | Cosmetic | Same secret still in JS |
| Websockify token plugin | Partial | Scopes tunnel target; RFB password still in browser |
| RFB-terminating proxy (e.g. Guacamole) | Yes, but large redesign | Password stays server-side |
| Provider ephemeral tickets only | Provider-specific | VMRC already differs; Libvirt VNC does not |

**Conclusion:** Full remediation requires replacing the websockify+noVNC
password path with a server-side RFB (or provider) proxy. That is out of
scope for a minimal Foreman patch.

## Implementation plan (full fix)

1. Introduce a console gateway process that speaks RFB to the hypervisor
   using the server-held session password.
2. Authenticate the browser to the gateway with a short-lived,
   host-bound ticket issued only after Foreman authorization (+ reauth).
3. Ticket properties: high entropy, host/VM binding, short TTL, single-use
   or hard expiry, rejected after logout/session end.
4. Point the HTML client at the gateway **without** embedding the hypervisor
   VNC password (Guacamole client or noVNC against a passwordless local
   listener bound to the gateway).
5. Do not publish raw websockify ports; revoke tickets on session end.
6. Cover Libvirt and VMware VNC; keep VMRC / OpenStack paths unchanged unless
   they share the same exposure.
7. Add tests: unauthorized console denied; cross-host ticket rejected;
   expired ticket rejected; HTML/network free of hypervisor VNC password.

## Mitigations shipped with F-025 (not full remediation)

- `Cache-Control: private, no-store` on console HTML responses
- Optional reauthentication before opening a console
- Architecture documented here (do not treat DOM attribute removal as a fix)
