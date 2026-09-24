Foreman::SettingManager.define(:foreman) do
  category(:auth, N_('Authentication')) do
    setting('oauth_active',
      type: :boolean,
      description: N_("Foreman will use OAuth for API authorization"),
      default: false,
      full_name: N_('OAuth active'))
    setting('oauth_consumer_key',
      type: :string,
      description: N_("OAuth consumer key"),
      default: '',
      full_name: N_('OAuth consumer key'),
      encrypted: true)
    setting('oauth_consumer_secret',
      type: :string,
      description: N_("OAuth consumer secret"),
      default: '',
      full_name: N_("OAuth consumer secret"),
      encrypted: true)
    setting('oauth_map_users',
      type: :boolean,
      description: N_("When enabled, Foreman will map users by username in request-header. If this is disabled, OAuth requests will have admin rights."),
      default: true,
      full_name: N_('OAuth map users'))
    setting('failed_login_attempts_limit',
      type: :integer,
      description: N_("Foreman will block user logins from an IP address after this number of failed login attempts for 5 minutes. Set to 0 to disable bruteforce protection"),
      default: 30,
      full_name: N_('Failed login attempts limit'))
    setting('captcha_enabled',
      type: :boolean,
      description: N_("Require an offline CAPTCHA challenge for interactive password logins. The challenge is generated and verified entirely on the Foreman server (no external network)."),
      default: false,
      full_name: N_('Login CAPTCHA'))
    setting('account_lockout_attempts',
      type: :integer,
      description: N_("Number of consecutive failed password attempts against a local (internal) user account within the lockout window before the account is temporarily locked. Does not apply to LDAP or external authentication providers."),
      default: 5,
      full_name: N_('Account lockout attempts'))
    setting('account_lockout_window',
      type: :integer,
      description: N_("Time window in minutes during which failed password attempts against a local user account are counted toward account lockout."),
      default: 15,
      full_name: N_('Account lockout window (minutes)'))
    setting('account_lockout_duration',
      type: :integer,
      description: N_("How long in minutes a local user account remains locked after reaching the failed password attempt threshold. The account unlocks automatically when this period expires."),
      default: 30,
      full_name: N_('Account lockout duration (minutes)'))
    setting('restrict_registered_smart_proxies',
      type: :boolean,
      description: N_('Only known Smart Proxies may access features that use Smart Proxy authentication'),
      default: true,
      full_name: N_('Restrict registered smart proxies'))
    setting('trusted_hosts',
      type: :array,
      description: N_('List of hostnames, IPv4, IPv6 addresses or subnets to be trusted in addition to Smart Proxies for access to fact/report importers and ENC output'),
      default: [],
      full_name: N_('Trusted hosts'))
    setting('ssl_certificate',
      type: :string,
      description: N_("SSL Certificate path that Foreman would use to communicate with its proxies"),
      default: nil,
      full_name: N_('SSL certificate'))
    setting('ssl_ca_file',
      type: :string,
      description: N_("SSL CA file path that Foreman will use to communicate with its proxies"),
      default: nil,
      full_name: N_('SSL CA file'))
    setting('ssl_priv_key',
      type: :string,
      description: N_("SSL Private Key path that Foreman will use to communicate with its proxies"),
      default: nil,
      full_name: N_('SSL private key'))
    setting('ssl_client_dn_env',
      type: :string,
      description: N_('Environment variable containing the subject DN from a client SSL certificate'),
      default: 'SSL_CLIENT_S_DN',
      full_name: N_('SSL client DN env'))
    setting('ssl_client_verify_env',
      type: :string,
      description: N_('Environment variable containing the verification status of a client SSL certificate'),
      default: 'SSL_CLIENT_VERIFY',
      full_name: N_('SSL client verify env'))
    setting('ssl_client_cert_env',
      type: :string,
      description: N_("Environment variable containing a client's SSL certificate"),
      default: 'SSL_CLIENT_CERT',
      full_name: N_('SSL client cert env'))
    setting('server_ca_file',
      type: :string,
      description: N_("SSL CA file path that will be used in templates (to verify the connection to Foreman)"),
      default: nil,
      full_name: N_('Server CA file'))

    setting('websockets_ssl_key',
      type: :string,
      description: N_("Private key file path that Foreman will use to encrypt websockets"),
      default: nil,
      full_name: N_('Websockets SSL key'))
    setting('websockets_ssl_cert',
      type: :string,
      description: N_("Certificate path that Foreman will use to encrypt websockets"),
      default: nil,
      full_name: N_('Websockets SSL certificate'))
    # websockets_encrypt depends on key/cert when true, so initialize it last
    setting('websockets_encrypt',
      type: :boolean,
      description: N_("VNC/SPICE websocket proxy console access encryption (websockets_ssl_key/cert setting required)"),
      default: !!SETTINGS[:require_ssl], # rubocop:disable Style/DoubleNegation
      full_name: N_('Websockets encryption'))
    validates('websockets_encrypt', ->(value) { !value || !(Setting["websockets_ssl_key"].empty? || Setting["websockets_ssl_cert"].empty?) }, message: N_("Unable to turn on websockets_encrypt, either websockets_ssl_key or websockets_ssl_cert is missing"))
    validates('websockets_ssl_key', ->(value) { !Setting["websockets_encrypt"] || !value.empty? }, message: N_("Unable to unset websockets_ssl_key when websockets_encrypt is on"))
    validates('websockets_ssl_cert', ->(value) { !Setting["websockets_encrypt"] || !value.empty? }, message: N_("Unable to unset websockets_ssl_cert when websockets_encrypt is on"))

    setting('login_delegation_logout_url',
      type: :string,
      description: N_('Redirect your users to this url on logout (authorize_login_delegation should also be enabled)'),
      default: nil,
      full_name: N_('Login delegation logout URL'))
    setting('authorize_login_delegation_auth_source_user_autocreate',
      type: :string,
      description: N_('Name of the external auth source where unknown externally authentication users (see authorize_login_delegation) should be created. Empty means no autocreation.'),
      default: 'External',
      full_name: N_('Authorize login delegation auth source user autocreate'))
    setting('authorize_login_delegation',
      type: :boolean,
      description: N_("Authorize login delegation with REMOTE_USER HTTP header"),
      default: false,
      full_name: N_('Authorize login delegation'))
    setting('authorize_login_delegation_api',
      type: :boolean,
      description: N_("Authorize login delegation with REMOTE_USER HTTP header for API calls too"),
      default: false,
      full_name: N_('Authorize login delegation API'))
    setting('idle_timeout',
      type: :integer,
      description: N_("Log out idle users after a certain number of minutes"),
      default: 60,
      full_name: N_('Idle timeout'))
    setting('password_hash',
      type: :string,
      description: N_("Password hashing algorithm. A password change is needed effect existing passwords."),
      default: 'bcrypt',
      full_name: N_('Password hashing algorithm'),
      collection: proc { { 'sha1' => _("SHA1"), 'bcrypt' => _("BCrypt"), 'pbkdf2sha1' => _("PBKDF2 SHA1") } })
    setting('bcrypt_cost',
      type: :integer,
      description: N_("Cost value of bcrypt password hash function for internal auth-sources (4-30). A higher value is safer but verification is slower, particularly for stateless API calls and UI logins. A password change is needed effect existing passwords."),
      default: 4,
      full_name: N_('BCrypt password cost'))
    setting('pbkdf2_cost',
      type: :integer,
      description: N_("Cost value of PBKDF2 password hash function for internal auth-sources. A higher value is safer but verification is slower, particularly for stateless API calls and UI logins. A password change is needed effect existing passwords."),
      default: 50000,
      full_name: N_('PBKDF2 password cost'))
    setting('bmc_credentials_accessible',
      type: :boolean,
      description: N_("Permits access to BMC interface passwords through ENC YAML output and in templates"),
      default: false,
      full_name: N_('BMC credentials access'))
    setting('oidc_jwks_url',
      type: :string,
      description: N_("OpenID Connect JSON Web Key Set(JWKS) URL. Typically https://keycloak.example.com/auth/realms/<realm name>/protocol/openid-connect/certs when using Keycloak as an OpenID provider"),
      default: nil,
      full_name: N_('OIDC JWKs URL'))
    setting('oidc_audience',
      type: :array,
      description: N_("Name of the OpenID Connect Audience that is being used for Authentication. In case of Keycloak this is the Client ID."),
      default: [],
      full_name: N_('OIDC Audience'))
    setting('oidc_issuer',
      type: :string,
      description: N_("The iss (issuer) claim identifies the principal that issued the JWT, which exists at a `/.well-known/openid-configuration` in case of most of the OpenID providers."),
      default: nil,
      full_name: N_('OIDC Issuer'))
    setting('oidc_algorithm',
      type: :string,
      description: N_("The algorithm used to encode the JWT in the OpenID provider."),
      default: nil,
      full_name: N_('OIDC Algorithm'))

    # Step-up / re-authentication (policy infrastructure; sensitive-action enforcement is later)
    setting('reauthentication_window_minutes',
      type: :integer,
      description: N_("How long in minutes a successful re-authentication remains valid for sensitive actions in the same browser session. Changing this setting always requires re-authentication."),
      default: 5,
      full_name: N_('Re-authentication window (minutes)'))
    validates('reauthentication_window_minutes',
      ->(value) { value.to_i.between?(1, 30) },
      message: N_("must be between 1 and 30"))

    setting('require_reauth_users_set_admin',
      type: :boolean,
      description: N_("Require re-authentication before granting or revoking the administrator flag on a user"),
      default: true,
      full_name: N_('Require re-authentication to change admin flag'))
    setting('require_reauth_users_set_disabled',
      type: :boolean,
      description: N_("Require re-authentication before enabling or disabling a user account"),
      default: true,
      full_name: N_('Require re-authentication to enable/disable users'))
    setting('require_reauth_users_impersonate',
      type: :boolean,
      description: N_("Require re-authentication before impersonating another user"),
      default: true,
      full_name: N_('Require re-authentication to impersonate'))
    setting('require_reauth_auth_sources_update',
      type: :boolean,
      description: N_("Require re-authentication before updating an authentication source (e.g. LDAP)"),
      default: true,
      full_name: N_('Require re-authentication to update auth sources'))
    setting('require_reauth_users_destroy',
      type: :boolean,
      description: N_("Require re-authentication before deleting a user"),
      default: true,
      full_name: N_('Require re-authentication to delete users'))
    setting('require_reauth_users_change_password',
      type: :boolean,
      description: N_("Require re-authentication before changing another user's password"),
      default: true,
      full_name: N_('Require re-authentication to change other users passwords'))
    setting('require_reauth_users_change_roles',
      type: :boolean,
      description: N_("Require re-authentication before changing user role membership or role/filter definitions"),
      default: true,
      full_name: N_('Require re-authentication to change roles'))
    setting('require_reauth_auth_sources_create',
      type: :boolean,
      description: N_("Require re-authentication before creating an authentication source"),
      default: true,
      full_name: N_('Require re-authentication to create auth sources'))
    setting('require_reauth_auth_sources_destroy',
      type: :boolean,
      description: N_("Require re-authentication before deleting an authentication source"),
      default: true,
      full_name: N_('Require re-authentication to delete auth sources'))
    setting('require_reauth_users_terminate_sessions',
      type: :boolean,
      description: N_("Require re-authentication before terminating user sessions"),
      default: true,
      full_name: N_('Require re-authentication to terminate sessions'))
    setting('require_reauth_users_invalidate_jwt',
      type: :boolean,
      description: N_("Require re-authentication before invalidating user registration JWTs"),
      default: true,
      full_name: N_('Require re-authentication to invalidate JWTs'))
    setting('require_reauth_users_create',
      type: :boolean,
      description: N_("Require re-authentication before creating a user"),
      default: true,
      full_name: N_('Require re-authentication to create users'))
    setting('require_reauth_personal_access_tokens_create',
      type: :boolean,
      description: N_("Require re-authentication before creating a personal access token"),
      default: true,
      full_name: N_('Require re-authentication to create personal access tokens'))
    setting('require_reauth_personal_access_tokens_revoke',
      type: :boolean,
      description: N_("Require re-authentication before revoking a personal access token"),
      default: true,
      full_name: N_('Require re-authentication to revoke personal access tokens'))
    setting('require_reauth_ssh_keys_create',
      type: :boolean,
      description: N_("Require re-authentication before adding an SSH public key to a user"),
      default: true,
      full_name: N_('Require re-authentication to create SSH keys'))
    setting('require_reauth_ssh_keys_destroy',
      type: :boolean,
      description: N_("Require re-authentication before deleting a user SSH public key"),
      default: true,
      full_name: N_('Require re-authentication to delete SSH keys'))
    setting('require_reauth_registration_commands_create',
      type: :boolean,
      description: N_("Require re-authentication before generating a host registration command (issues a registration JWT)"),
      default: true,
      full_name: N_('Require re-authentication to generate registration commands'))
    setting('require_reauth_key_pairs_download',
      type: :boolean,
      description: N_("Require re-authentication before downloading a compute resource SSH private key (PEM)"),
      default: true,
      full_name: N_('Require re-authentication to download compute SSH private keys'))
    setting('require_reauth_key_pairs_recreate',
      type: :boolean,
      description: N_("Require re-authentication before recreating a compute resource SSH key pair"),
      default: true,
      full_name: N_('Require re-authentication to recreate compute SSH key pairs'))
    setting('require_reauth_key_pairs_destroy',
      type: :boolean,
      description: N_("Require re-authentication before deleting a compute resource SSH key"),
      default: true,
      full_name: N_('Require re-authentication to delete compute SSH keys'))
  end
end
