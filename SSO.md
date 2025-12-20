# SSO Authentication

sstart supports Single Sign-On (SSO) authentication via OIDC (OpenID Connect). When SSO is configured, sstart will automatically authenticate users before fetching secrets from providers. The obtained access token can then be used by providers that require OIDC-based authentication.

## How It Works

1. When you run `sstart -- your-command`, sstart checks if SSO is configured in `.sstart.yml`
2. If configured, sstart checks for existing valid tokens (stored in `~/.config/sstart/tokens.json`)
3. If no valid tokens exist or they are expired:
   - A local HTTP server starts on port 5747
   - Your default browser opens to the OIDC provider's login page
   - After successful authentication, tokens are cached locally
4. The access token is made available to providers for authentication
5. Secrets are fetched from providers and injected into your subprocess

## Configuration

Add the `sso` section to your `.sstart.yml`:

```yaml
sso:
  oidc:
    clientId: your-client-id        # Required: OIDC client ID
    issuer: https://auth.example.com # Required: OIDC issuer URL
    scopes:                          # Required: OIDC scopes
      - openid
      - profile
      - email

providers:
  - kind: vault
    path: secret/myapp
```

### Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| `clientId` | Yes | The OIDC client ID registered with your identity provider |
| `issuer` | Yes | The OIDC issuer URL (e.g., `https://auth.example.com`) |
| `scopes` | Yes | List of OIDC scopes to request. Must include at least one scope. Common scopes: `openid`, `profile`, `email` |
| `pkce` | No | Explicitly enable PKCE flow (`true`/`false`). Defaults to `true` when client secret is not set |
| `redirectUri` | No | Custom redirect URI. Defaults to `http://localhost:5747/auth/sstart` |
| `responseMode` | No | OIDC response mode (e.g., `query`, `fragment`) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SSTART_SSO_SECRET` | The OIDC client secret. When set, disables PKCE and uses client secret authentication |

### Scopes Format

Scopes can be specified as either an array or a space-separated string:

```yaml
# Array format
scopes:
  - openid
  - profile
  - email

# Space-separated string format
scopes: "openid profile email"
```

## Authentication Flow

### PKCE (Recommended for Public Clients)

When `clientSecret` is not provided (or `pkce: true` is set), sstart uses the PKCE (Proof Key for Code Exchange) flow. This is the recommended approach for CLI applications as it doesn't require storing a client secret.

```yaml
sso:
  oidc:
    clientId: my-public-client
    issuer: https://auth.example.com
    scopes:
      - openid
      - profile
```

### Confidential Client

For confidential clients that require a client secret, set the secret via the `SSTART_SSO_SECRET` environment variable:

```bash
export SSTART_SSO_SECRET="your-client-secret"
```

Then configure the OIDC settings (without the secret in the config file):

```yaml
sso:
  oidc:
    clientId: my-confidential-client
    issuer: https://auth.example.com
    scopes:
      - openid
      - profile
```

**Note**: The client secret is intentionally not stored in the config file to avoid committing secrets to version control.

## Token Storage

sstart stores SSO tokens securely using the system keyring when available, with automatic fallback to file storage.

### Storage Backends

| Backend | Platform | Description |
|---------|----------|-------------|
| **Keyring** (default) | macOS, Windows, Linux | Uses the OS-native secure credential storage |
| **File** (fallback) | All platforms | Falls back to `~/.config/sstart/tokens.json` with 0600 permissions |

#### Keyring Support

- **macOS**: Keychain
- **Windows**: Windows Credential Manager  
- **Linux**: Secret Service (GNOME Keyring, KWallet, etc.)

sstart automatically detects if keyring is available. If not (e.g., in CI/CD environments, headless servers, or containers), it falls back to file-based storage.

### Stored Tokens

The following tokens are stored:

- **Access Token**: Used for authenticating with providers
- **Refresh Token**: Used to obtain new access tokens when expired
- **ID Token**: Contains user identity claims
- **Expiry**: Token expiration timestamp

### Token Refresh

When tokens expire, sstart automatically attempts to refresh them using the refresh token. If refresh fails (e.g., refresh token expired), a new authentication flow is initiated.

## Provider Integration

Providers can access SSO tokens via their configuration to authenticate API requests. The tokens are injected into the provider config with special keys:

| Config Key | Description |
|------------|-------------|
| `_sso_access_token` | The OIDC access token |
| `_sso_id_token` | The OIDC ID token |

Providers that support OIDC authentication can use these tokens to authenticate their API calls. For example, a provider could use the access token as a Bearer token:

```go
// Inside a provider's Fetch implementation
if accessToken, ok := config["_sso_access_token"].(string); ok {
    req.Header.Set("Authorization", "Bearer "+accessToken)
}
```

**Note**: SSO tokens are only used for provider authentication. They are NOT injected as environment variables into the subprocess.

## Example Configurations

### With Keycloak

```yaml
sso:
  oidc:
    clientId: sstart-cli
    issuer: https://keycloak.example.com/realms/myrealm
    scopes:
      - openid
      - profile
      - email

providers:
  - kind: vault
    address: https://vault.example.com
    path: secret/myapp
```

### With Auth0

```yaml
sso:
  oidc:
    clientId: abc123xyz
    issuer: https://your-tenant.auth0.com
    scopes:
      - openid
      - profile
      - email
```

### With Okta

```yaml
sso:
  oidc:
    clientId: 0oaxxxxxxxx
    issuer: https://your-org.okta.com
    scopes:
      - openid
      - profile
      - email
```

### With Google

```yaml
sso:
  oidc:
    clientId: your-client-id.apps.googleusercontent.com
    issuer: https://accounts.google.com
    scopes:
      - openid
      - profile
      - email
```

### With Azure AD / Entra ID

```yaml
sso:
  oidc:
    clientId: your-application-id
    issuer: https://login.microsoftonline.com/your-tenant-id/v2.0
    scopes:
      - openid
      - profile
      - email
```

## Troubleshooting

### Browser Doesn't Open

If the browser doesn't open automatically, the login URL will be printed to the terminal. Copy and paste it into your browser manually.

```
🔐 Opening browser for authentication...
   If the browser doesn't open, visit: http://localhost:5747/login
```

### Port Already in Use

If port 5747 is already in use, the authentication will fail. Ensure no other application is using this port, or wait for the previous sstart process to complete.

### Token Expired

If you see authentication errors, your tokens may have expired and the refresh token is no longer valid. sstart will automatically initiate a new login flow.

### Clearing Tokens

To force a fresh login, you can use the `--force-auth` flag:

```bash
sstart --force-auth show
```

Or manually clear the stored tokens:

**macOS** (Keychain):
```bash
security delete-generic-password -s sstart -a sso-tokens
```

**Linux** (if using file fallback):
```bash
rm ~/.config/sstart/tokens.json
```

**Windows** (Credential Manager):
Use the Windows Credential Manager UI to remove the "sstart" credential.

### Authentication Timeout

The authentication flow times out after 5 minutes. If you don't complete the login within this time, sstart will fail with a timeout error. Simply run the command again to restart the authentication.

## Vault / OpenBao Integration

When using SSO with HashiCorp Vault or OpenBao, sstart can use the OIDC tokens to authenticate with Vault's JWT auth backend. This allows users to access secrets without managing static Vault tokens.

### How It Works

1. User authenticates via OIDC (e.g., with Zitadel, Keycloak, Okta)
2. sstart obtains an ID token from the OIDC provider
3. The ID token is sent to Vault/OpenBao's JWT auth backend
4. Vault validates the token and returns a Vault token
5. sstart uses the Vault token to fetch secrets

### sstart Configuration

Configure the Vault provider with the `auth` block:

```yaml
sso:
  oidc:
    clientId: your-client-id
    issuer: https://auth.example.com
    scopes:
      - openid
      - profile
      - email

providers:
  - kind: vault
    address: https://vault.example.com
    path: secret/myapp
    auth:
      method: oidc          # or "jwt" - both work the same way
      role: your-vault-role # Required: the JWT auth role in Vault
      mount: jwt            # Optional: auth backend mount path (default: "jwt")
```

#### Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| `auth.method` | Yes | Set to `oidc` or `jwt` to use SSO tokens for authentication |
| `auth.role` | Yes | The Vault JWT auth role name to authenticate as |
| `auth.mount` | No | The mount path of the JWT auth backend (default: `jwt`) |

### Vault / OpenBao Setup

You need to configure Vault/OpenBao to accept JWT tokens from your OIDC provider.

#### 1. Enable JWT Auth Backend

```bash
# For Vault
vault auth enable jwt

# For OpenBao
bao auth enable jwt
```

#### 2. Configure the JWT Auth Backend

Configure the backend to trust your OIDC provider:

```bash
# For Vault
vault write auth/jwt/config \
  oidc_discovery_url="https://auth.example.com" \
  default_role="sstart"

# For OpenBao
bao write auth/jwt/config \
  oidc_discovery_url="https://auth.example.com" \
  default_role="sstart"
```

Replace `https://auth.example.com` with your OIDC issuer URL.

#### 3. Create a JWT Auth Role

Create a role that maps OIDC users to Vault policies:

```bash
# For Vault
vault write auth/jwt/role/sstart \
  role_type="jwt" \
  bound_audiences="your-client-id" \
  user_claim="sub" \
  policies="your-policy" \
  ttl="1h"

# For OpenBao
bao write auth/jwt/role/sstart \
  role_type="jwt" \
  bound_audiences="your-client-id" \
  user_claim="sub" \
  policies="your-policy" \
  ttl="1h"
```

**Important**: 
- `role_type` must be `jwt` (not `oidc`) because sstart passes the token directly
- `bound_audiences` must match your OIDC client ID exactly

#### 4. Create a Policy

Create a policy that grants access to your secrets:

```bash
# Create policy file
cat > sstart-policy.hcl << EOF
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}
EOF

# For Vault
vault policy write sstart-policy sstart-policy.hcl

# For OpenBao
bao policy write sstart-policy sstart-policy.hcl
```

### Example: Complete Setup with Zitadel

#### Zitadel Configuration

1. Create an application in Zitadel with:
   - Application Type: Native (for PKCE) or Web (for client secret)
   - Redirect URI: `http://localhost:5747/auth/sstart`

2. Note your Client ID (e.g., `351633448147908967`)

#### OpenBao/Vault Configuration

```bash
# Enable JWT auth
bao auth enable jwt

# Configure to trust Zitadel
bao write auth/jwt/config \
  oidc_discovery_url="https://your-instance.zitadel.cloud"

# Create role
bao write auth/jwt/role/sstart \
  role_type="jwt" \
  bound_audiences="351633448147908967" \
  user_claim="sub" \
  policies="sstart-policy" \
  ttl="1h"

# Create policy for reading secrets
bao policy write sstart-policy - << EOF
path "secret/data/*" {
  capabilities = ["read", "list"]
}
EOF
```

#### sstart Configuration

```yaml
sso:
  oidc:
    clientId: 351633448147908967
    issuer: https://your-instance.zitadel.cloud
    scopes:
      - openid
      - profile
      - email

providers:
  - kind: vault
    address: https://vault.example.com
    path: secret/myapp
    auth:
      method: oidc
      role: sstart
      mount: jwt
```

### Using Client Secret (Non-PKCE)

Some OIDC providers or Vault configurations may not support PKCE. In this case, set the client secret via environment variable:

```bash
export SSTART_SSO_SECRET="your-client-secret"
sstart show
```

The environment variable takes precedence over any `clientSecret` in the config file, keeping secrets out of version control.

### Troubleshooting Vault SSO

#### "permission denied" Error

This usually means the JWT validation failed. Check:

1. **Audience mismatch**: Verify `bound_audiences` matches your OIDC client ID exactly
   ```bash
   bao read auth/jwt/role/sstart
   ```

2. **Issuer not configured**: Verify the OIDC discovery URL is set
   ```bash
   bao read auth/jwt/config
   ```

3. **Role doesn't exist**: Verify the role exists
   ```bash
   bao list auth/jwt/role
   ```

#### "role with oidc role_type is not allowed" Error

The role is configured with `role_type="oidc"` but sstart requires `role_type="jwt"`. Update the role:

```bash
bao write auth/jwt/role/sstart \
  role_type="jwt" \
  bound_audiences="your-client-id" \
  user_claim="sub" \
  policies="your-policy" \
  ttl="1h"
```

#### "empty client secret" Error

Your OIDC provider requires a client secret but it's not set. Set it via environment variable:

```bash
export SSTART_SSO_SECRET="your-client-secret"
```

## Security Considerations

1. **Token Storage**: Tokens are stored in the system keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) when available. This provides OS-level encryption and access control. Falls back to file storage with restrictive permissions (0600) when keyring is unavailable.

2. **PKCE**: When possible, use PKCE flow (don't provide `clientSecret`) for better security in CLI applications.

3. **Localhost Callback**: The callback server only binds to `127.0.0.1`, preventing external access.

4. **Session Cookies**: Secure, HTTP-only cookies are used during the authentication flow.

5. **No Token Injection**: SSO tokens are NOT injected into subprocess environment variables, limiting exposure.

6. **Client Secret via Environment**: Use `SSTART_SSO_SECRET` environment variable instead of storing secrets in config files.

