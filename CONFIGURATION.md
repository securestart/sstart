# Configuration

The `.sstart.yml` file defines your providers and secret mappings.

> **SSO Authentication**: sstart supports OIDC-based Single Sign-On for provider authentication. See [SSO.md](SSO.md) for details on configuring SSO.

## Basic Structure

```yaml
inherit: true  # Optional: whether to inherit system environment variables (default: true)
              # Set to false to only use secrets from providers (clean environment)

providers:
  - kind: provider_kind
    id: provider_id  # Optional: defaults to 'kind'. Required if multiple providers share the same 'kind'
    path: path/to/secret
    keys:
      SOURCE_KEY: TARGET_KEY
      ANOTHER_KEY: ==  # == means keep same name
```

**Important**: Each provider loads from a single source. If you need to load multiple secrets from the same provider type (e.g., multiple paths from AWS Secrets Manager), configure multiple provider instances with the same `kind` but different `id` values. When multiple providers share the same `kind`, each must have an explicit, unique `id`.

## Provider Kinds

| Provider | Status |
|----------|--------|
| `1password` | Stable |
| `aws_secretsmanager` | Stable |
| `azure_keyvault` | Stable |
| `bitwarden` | Stable |
| `bitwarden_sm` | Stable |
| `doppler` | Stable |
| `dotenv` | Stable |
| `gcloud_secretmanager` | Stable |
| `infisical` | Stable |
| `template` | Stable |
| `vault` | Stable |

## Provider Configuration

### 1Password (`1password`)

Retrieves secrets from 1Password using the 1Password Connect SDK. Supports fetching individual fields, whole sections, or entire items from 1Password vaults.

**Dependencies:**
- No CLI required. Uses the 1Password Go SDK directly.

**Configuration:**
- `ref` (required): The 1Password secret reference in the format `op://<vault>/<item>/[section/]<field>`. sstart supports custom reference formats that allow fetching different scopes of secrets:
  - `op://VaultName/ItemName/fieldName` - Fetch a specific top-level field (not in any section)
  - `op://VaultName/ItemName/sectionName/fieldName` - Fetch a specific field from a section
  - `op://VaultName/ItemName/sectionName` - **Fetch all fields from a section** (custom sstart feature)
  - `op://VaultName/ItemName` - **Fetch all fields from an entire item** (custom sstart feature)
- `use_section_prefix` (optional): When `true`, fields from sections will have keys prefixed with the section name (e.g., `SectionName_FieldName`). When `false` or not specified, fields use just the field name. Defaults to `false`.

**Reference Format Support:**
sstart extends the standard 1Password reference format to support fetching multiple secrets at once:
- **Single field references** (`op://vault/item/field` or `op://vault/item/section/field`): Fetch one specific field value
- **Whole section references** (`op://vault/item/section`): Fetch all fields from a specific section in an item. All fields from that section will be loaded as environment variables.
- **Whole item references** (`op://vault/item`): Fetch all fields from an entire item, including both top-level fields and fields from all sections. This is useful when you want to load all secrets from an item at once.

**Authentication:**
1Password authentication must be provided via environment variable:
- `OP_SERVICE_ACCOUNT_TOKEN` (required): Service account token for 1Password Connect API authentication

**Example - Fetch a specific field:**
```yaml
providers:
  - kind: 1password
    id: onepassword-prod
    ref: op://Production/MyApp/API_KEY
```

**Example - Fetch a whole section:**
```yaml
providers:
  - kind: 1password
    id: onepassword-db
    ref: op://Production/MyApp/Database
```

This example fetches all fields from the "Database" section. All fields from the section will be loaded as environment variables.

**Example - Fetch whole item with section prefixes:**
```yaml
providers:
  - kind: 1password
    id: onepassword-app
    ref: op://Production/MyApp
    use_section_prefix: true
```

This example fetches all fields from the entire item. With `use_section_prefix: true`, fields from sections are prefixed (e.g., `Database_HOST`), while top-level fields remain unprefixed (e.g., `API_KEY`).

**Example - Fetch whole item without section prefixes:**
```yaml
providers:
  - kind: 1password
    id: onepassword-app
    ref: op://Production/MyApp
    use_section_prefix: false
```

This example fetches all fields from the entire item without section prefixes. Field names will be just the field names (e.g., `HOST`, `PORT`). Top-level fields take precedence over section fields with the same name (warnings are logged). If the same field name exists in multiple sections, an error will be raised to prevent collisions.

**Section Prefix Behavior:**
- **Default (no prefix)**: When `use_section_prefix` is not specified or set to `false`, fields use just their field names (e.g., `HOST`, `PORT`). This works well when field names are unique across sections.
- **With prefix**: When `use_section_prefix: true`, fields from sections are prefixed with the section name (e.g., `Database_HOST`, `Database_PORT`). This prevents collisions when the same field name exists in multiple sections.

**Collision Handling and Priority:**
When fetching secrets without section prefixes, sstart handles collisions with a clear priority system:

1. **Top-level fields take precedence**: If a field name exists both as a top-level field and in a section, the top-level field value will be used. A warning will be logged suggesting how to access the section field instead.

2. **Ambiguous references**: When using a reference like `op://vault/item/DB` where both a top-level field "DB" and a section "DB" exist, sstart will:
   - Use the top-level field (priority)
   - Log a warning about the ambiguous reference
   - Suggest renaming either the top-level field or the section in 1Password to avoid ambiguity, or use `use_section_prefix: true` when fetching the whole item to access both

3. **Section-to-section collisions**: If the same field name exists in multiple sections (e.g., `HOST` in both "Database" and "Redis" sections), sstart will return an error. Use `use_section_prefix: true` to load both fields with distinct names.

**Examples of collision handling:**

- **Top-level field vs section field**: If item has top-level field `DB` and section `DB` with field `HOST`:
  - `op://vault/item/DB` → Uses top-level field `DB`, warns about section
  - `op://vault/item` → Uses top-level field `DB`, section field `HOST` is loaded (no collision)
  - If section `DB` also had a field named `DB`, the top-level field takes precedence, and a warning is logged

- **Multiple sections with same field name**: If item has `HOST` in both "Database" and "Redis" sections:
  - `op://vault/item` (without prefix) → Error: collision detected
  - `op://vault/item` with `use_section_prefix: true` → Loads both as `Database_HOST` and `Redis_HOST`

**How it works:**
The provider uses the 1Password Connect SDK to authenticate with 1Password Connect (or 1Password Business/Enterprise) using a service account token. It resolves vault and item names to IDs, then retrieves the specified secrets. 

sstart implements custom support for 1Password reference formats beyond single-field references:
- **Section-level fetching** (`op://vault/item/section`): When a reference points to a section (without a field name), sstart fetches all fields within that section and makes them available as environment variables.
- **Item-level fetching** (`op://vault/item`): When a reference points to just a vault and item (without section or field), sstart fetches all fields from the entire item, including top-level fields and fields from all sections.

This custom implementation allows you to efficiently load multiple secrets in a single provider configuration, rather than requiring separate provider entries for each field.

**1Password Connect Setup:**
To use this provider, you need:
1. 1Password Connect server running (or access to 1Password Business/Enterprise)
2. A service account token created in your 1Password account
3. The service account must have access to the vaults and items you want to retrieve

For more information on setting up 1Password Connect, see the [1Password Connect documentation](https://developer.1password.com/docs/connect).

### AWS Secrets Manager (`aws_secretsmanager`)

Retrieves secrets from AWS Secrets Manager. Supports both JSON secrets (parsed into multiple key-value pairs) and plain text secrets.

**Configuration:**
- `secret_id` (required): The ARN or name of the secret in AWS Secrets Manager
- `region` (optional): The AWS region where the secret is stored
- `endpoint` (optional): Custom endpoint URL for AWS Secrets Manager (useful for local testing with LocalStack)

**Authentication:**
AWS Secrets Manager uses the AWS SDK's default credential chain, which supports:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- AWS credentials file (`~/.aws/credentials`)
- IAM roles (when running on EC2/ECS/Lambda)
- AWS SSO

**Example:**
```yaml
providers:
  - kind: aws_secretsmanager
    id: aws-prod
    secret_id: myapp/production
    region: us-east-1
```

**JSON Secrets:**
If the secret value in AWS Secrets Manager is a JSON object, it will be automatically parsed and each key-value pair will be mapped according to the `keys` configuration. If `keys` is empty, all keys from the JSON will be mapped.

**Plain Text Secrets:**
If the secret value is plain text (not JSON), it will be mapped to a single environment variable named `<PROVIDER_ID>_SECRET` (where `<PROVIDER_ID>` is the provider's ID in uppercase, with hyphens converted to underscores). A warning will be logged indicating that the secret is not in JSON format.

For example, if the provider ID is `aws-prod`, the secret will be loaded to `AWS_PROD_SECRET`.

### Azure Key Vault (`azure_keyvault`)

Retrieves secrets from Azure Key Vault. Supports both JSON secrets (which are parsed into multiple key-value pairs) and plain text secrets.

**Configuration:**
- `vault_url` (required): The URL of the Azure Key Vault (e.g., `https://myvault.vault.azure.net/`)
- `secret_name` (required): The name of the secret in Azure Key Vault
- `version` (optional): The secret version to fetch (defaults to latest if not specified)

**Authentication:**
Azure Key Vault uses Azure's DefaultAzureCredential, which supports multiple authentication methods:
- Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
- Managed Identity (when running on Azure)
- Azure CLI authentication
- Visual Studio Code authentication

**Example:**
```yaml
providers:
  - kind: azure_keyvault
    id: azure-prod
    vault_url: https://myvault.vault.azure.net/
    secret_name: myapp/production
```

**JSON Secrets:**
If the secret value in Azure Key Vault is a JSON object, it will be automatically parsed and each key-value pair will be mapped according to the `keys` configuration. If `keys` is empty, all keys from the JSON will be mapped.

**Plain Text Secrets:**
If the secret value is plain text (not JSON), it will be mapped to a single environment variable named `<PROVIDER_ID>_SECRET` (where `<PROVIDER_ID>` is the provider's ID in uppercase, with hyphens converted to underscores). A warning will be logged indicating that the secret is not in JSON format.

For example, if the provider ID is `aws-prod`, the secret will be loaded to `AWS_PROD_SECRET`.

### Doppler (`doppler`)

Retrieves secrets from Doppler, a secrets management platform. Supports fetching all secrets from a specific project and config (environment) combination.

**Dependencies:**
- No CLI required. Uses the Doppler REST API directly.

**Configuration:**
- `project` (required): The Doppler project name
- `config` (required): The Doppler config/environment name (e.g., `dev`, `staging`, `prod`)
- `api_host` (optional): The Doppler API host (defaults to `https://api.doppler.com`)

**Authentication:**
Doppler authentication must be provided via environment variable:
- `DOPPLER_TOKEN` (required): Service token for Doppler API authentication

**Example:**
```yaml
providers:
  - kind: doppler
    id: doppler-prod
    project: myapp
    config: production
```

Set environment variable:
```bash
export DOPPLER_TOKEN="your-service-token"
```

**How it works:**
The provider uses the Doppler REST API to authenticate with Doppler using a service token. It fetches all secrets from the specified project and config combination, then makes them available as environment variables. Each secret key becomes an environment variable name.

The provider uses Doppler's "computed" values, which automatically resolve secret references (e.g., `${USER}` or `${OTHER_SECRET}`) to their actual values. Doppler's auto-generated secrets (`DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT`, `DOPPLER_PROJECT`) are automatically excluded from the fetched secrets.

**Service Token Setup:**
To use this provider, you need:
1. A Doppler account with a project and config set up
2. A service token created in your Doppler project with read access to the config
3. The service token must be set as the `DOPPLER_TOKEN` environment variable

For more information on creating service tokens, see the [Doppler documentation](https://docs.doppler.com/docs/service-tokens).

### Dotenv (`dotenv`)

Loads secrets from a `.env` file.

**Configuration:**
- `path` (required): Path to the `.env` file

**Example:**
```yaml
providers:
  - kind: dotenv
    id: dev
    path: .env.local
```

**Note:** The path supports environment variable expansion using `${VAR}` or `$VAR` syntax:
```yaml
  - kind: dotenv
    id: shared
    path: ${HOME}/.config/myapp/.env
```

### Google Cloud Secret Manager (`gcloud_secretmanager`)

Retrieves secrets from Google Cloud Secret Manager. Supports both JSON secrets (parsed into multiple key-value pairs) and plain text secrets.

**Configuration:**
- `project_id` (required): The GCP project ID where the secret is stored
- `secret_id` (required): The name of the secret in Google Cloud Secret Manager
- `version` (optional): The secret version to fetch (defaults to "latest" if not specified)
- `endpoint` (optional): Custom endpoint URL for GCSM (useful for local testing with emulator)

**Authentication:**
Google Cloud Secret Manager uses Application Default Credentials (ADC), which supports:
- Environment variable `GOOGLE_APPLICATION_CREDENTIALS` pointing to a service account key file
- GCP metadata server (when running on GCP)
- User credentials (when running `gcloud auth application-default login`)

**Example:**
```yaml
providers:
  - kind: gcloud_secretmanager
    id: gcp-prod
    project_id: my-gcp-project
    secret_id: myapp/production
    version: latest
```

**JSON Secrets:**
If the secret value in Google Cloud Secret Manager is a JSON object, it will be automatically parsed and each key-value pair will be mapped according to the `keys` configuration. If `keys` is empty, all keys from the JSON will be mapped.

**Plain Text Secrets:**
If the secret value is plain text (not JSON), it will be mapped to a single environment variable named `<PROVIDER_ID>_SECRET` (where `<PROVIDER_ID>` is the provider's ID in uppercase, with hyphens converted to underscores). A warning will be logged indicating that the secret is not in JSON format.

For example, if the provider ID is `aws-prod`, the secret will be loaded to `AWS_PROD_SECRET`.

### Infisical (`infisical`)

Retrieves secrets from Infisical, an open-source secrets management platform. Supports fetching secrets from specific paths within a project and environment, with options for recursive fetching, imports, and secret expansion.

**Dependencies:**
- No CLI required. Uses the Infisical Go SDK directly.

**Configuration:**
- `project_id` (required): The Infisical project ID where secrets are stored
- `environment` (required): The environment slug (e.g., `dev`, `prod`, `staging`)
- `path` (required): The secret path from where to fetch secrets (e.g., `/`, `/api`, `/database`)
- `recursive` (optional): Whether to fetch secrets recursively from subdirectories. Defaults to `false`
- `include_imports` (optional): Whether to include imported secrets. Defaults to `false`
- `expand_secrets` (optional): Whether to expand secret references. Defaults to `false`

**Authentication:**
Infisical authentication must be provided via environment variables:
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` (required): Client ID for Infisical Universal Auth
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` (required): Client secret for Infisical Universal Auth
- `INFISICAL_SITE_URL` (optional): Infisical server URL (defaults to `https://app.infisical.com` for self-hosted instances)

**Example:**
```yaml
providers:
  - kind: infisical
    id: infisical-prod
    project_id: proj-abc123-def456
    environment: production
    path: /api
```

**Example with optional parameters:**
```yaml
providers:
  - kind: infisical
    id: infisical-prod
    project_id: proj-abc123-def456
    environment: production
    path: /
    recursive: true
    include_imports: true
    expand_secrets: true
```

Set environment variables:
```bash
export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id"
export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret"
# Optional for self-hosted instances:
export INFISICAL_SITE_URL="https://infisical.example.com"
```

**How it works:**
The provider uses the Infisical Go SDK to authenticate with Infisical using Universal Auth credentials. It fetches secrets from the specified project, environment, and path, then makes them available as environment variables. Secrets are retrieved as key-value pairs where each secret's key becomes an environment variable name.

**Path Behavior:**
- Use `/` to fetch secrets from the root of the project
- Use `/path/to/secrets` to fetch secrets from a specific path
- When `recursive: true`, secrets from subdirectories are also included
- When `include_imports: true`, secrets imported from other projects are included
- When `expand_secrets: true`, secret references (e.g., `${OTHER_SECRET}`) are expanded to their actual values

### HashiCorp Vault / OpenBao (`vault`)

Retrieves secrets from HashiCorp Vault or OpenBao. Supports both KV v1 and KV v2 secret engines. OpenBao is a community-driven fork of HashiCorp Vault that maintains API compatibility, so the same `vault` provider works with both systems.

**Configuration:**
- `path` (required): The path to the secret in Vault
- `address` (optional): The Vault server address (defaults to `VAULT_ADDR` environment variable or `http://127.0.0.1:8200`)
- `token` (optional): The Vault authentication token (defaults to `VAULT_TOKEN` environment variable)
- `mount` (optional): The secret engine mount path (defaults to `secret`)

**Authentication:**
Vault authentication is done via token. The token can be provided:
- In the configuration file (`token` field)
- Via the `VAULT_TOKEN` environment variable

**Example:**
```yaml
providers:
  - kind: vault
    id: vault-prod
    address: https://vault.example.com:8200
    mount: secret
    path: myapp/production
```

**KV v1 and v2 Support:**
The provider automatically detects and supports both KV v1 and KV v2 secret engines. For KV v2, the data is automatically extracted from the `data` key.

**OpenBao Support:**
OpenBao is a community-driven, open-source fork of HashiCorp Vault that maintains full API compatibility. You can use the same `vault` provider configuration to connect to OpenBao instances. Simply point the `address` field to your OpenBao server URL:

```yaml
providers:
  - kind: vault
    id: openbao-prod
    address: https://openbao.example.com:8200
    mount: secret
    path: myapp/production
    token: your-openbao-token
```

The provider uses the same HashiCorp Vault API client, which is compatible with OpenBao's API. All features, including KV v1/v2 support, work identically with both Vault and OpenBao.

### Bitwarden (`bitwarden`)

Retrieves secrets from Bitwarden or Vaultwarden (self-hosted Bitwarden) personal vault using the Bitwarden CLI. Supports two formats: Note (JSON) or Fields (key-value pairs). Only Secure Note items (type 2) are supported.

**Dependencies:**
- Bitwarden CLI (`bw`) must be installed and available in your PATH. Install from https://bitwarden.com/help/cli/

**Configuration:**
- `item_id` (required): The ID of the item in Bitwarden vault. Can be found using `bw list items --search "item name"` or via Bitwarden web vault. Must be a Secure Note item (type 2)
- `format` (optional): How to parse the secret: `note` (JSON), `fields` (key-value pairs), or `both` (both notes and fields with fields taking precedence). Defaults to `both` if not specified
- `bw_path` (optional): Path to the Bitwarden CLI binary (defaults to `bw` in PATH)
- `server_url` (optional): The Bitwarden server URL (defaults to `BW_SERVER_URL` environment variable or `https://vault.bitwarden.com`)
- `api_port` (optional): Port for the local API server (defaults to `8087`)
- `api_hostname` (optional): Hostname for the local API server (defaults to `localhost`)

**Authentication:**
Bitwarden authentication must be provided via environment variables (credentials should never be stored in the config file):
- `BW_CLIENTID` (required): Bitwarden API client ID
- `BW_CLIENTSECRET` (required): Bitwarden API client secret
- `BW_PASSWORD` (required): Master password for unlocking the vault
- `BW_SERVER_URL` (optional): Bitwarden server URL for self-hosted instances
- `BW_PATH` (optional): Path to Bitwarden CLI binary if not in PATH
- `BW_SESSION` (optional): Existing session key (can be reused if already set)

**Example with Note format (JSON):**
```yaml
providers:
  - kind: bitwarden
    id: bitwarden-prod
    server_url: https://vault.bitwarden.com
    item_id: abc123-def456-ghi789
    format: note
```

Set environment variables:
```bash
export BW_CLIENTID="your-client-id"
export BW_CLIENTSECRET="your-client-secret"
export BW_PASSWORD="your-master-password"
# Optional for self-hosted instances:
export BW_SERVER_URL="https://vaultwarden.example.com"
```

**Example with Fields format (key-value pairs):**
```yaml
providers:
  - kind: bitwarden
    id: bitwarden-prod
    server_url: https://vault.bitwarden.com
    item_id: abc123-def456-ghi789
    format: fields
```

**Example with Both format (notes and fields):**
```yaml
providers:
  - kind: bitwarden
    id: bitwarden-prod
    server_url: https://vault.bitwarden.com
    item_id: abc123-def456-ghi789
    format: both
```

**Note Format:**
When `format: note` is specified, the provider parses the note content of the Bitwarden item as JSON. The note should contain a valid JSON object with key-value pairs.

**Fields Format:**
When `format: fields` is specified, the provider parses all custom fields of the Bitwarden item as key-value pairs. Each custom field's name becomes the key and its value becomes the environment variable value. If no custom fields are found, it will attempt to parse notes as JSON as a fallback.

**Both Format:**
When `format: both` is specified (or when `format` is not specified, as it's the default), the provider parses both the note content (as JSON) and all custom fields. If there are duplicate keys between notes and fields, the field values take precedence over note values. This allows you to use notes for most secrets and override specific values with custom fields.

**Vaultwarden Support:**
The provider works with both official Bitwarden and self-hosted Vaultwarden. Simply set the `server_url` to your Vaultwarden instance URL.

**How it works:**
The provider uses the Bitwarden CLI's REST API server (`bw serve`) to access your vault. It automatically starts a local API server, authenticates using your API credentials, unlocks the vault with your master password, and retrieves the specified Secure Note item.

**Supported Item Types:**
Only Secure Note items (type 2) are supported. Login items (type 1) and other item types are not supported.

### Bitwarden Secret Manager (`bitwarden_sm`)

Retrieves secrets from Bitwarden Secret Manager (organizational secrets). This provider uses the Bitwarden SDK to access secrets stored in a Secret Manager organization and project.

**Dependencies:**
- No CLI required. Uses the Bitwarden Go SDK directly.

**Configuration:**
- `organization_id` (required): The ID of the organization in Bitwarden Secret Manager
- `project_id` (required): The ID of the project in Bitwarden Secret Manager
- `server_url` (optional): The Bitwarden server URL (defaults to `BITWARDEN_SERVER_URL` environment variable or `https://vault.bitwarden.com`)

**Authentication:**
Bitwarden Secret Manager authentication must be provided via environment variables:
- `BITWARDEN_SM_ACCESS_TOKEN` (required): Access token for Bitwarden Secret Manager API authentication
- `BITWARDEN_SERVER_URL` (optional): Bitwarden server URL for self-hosted instances (defaults to `https://vault.bitwarden.com`)

**Example:**
```yaml
providers:
  - kind: bitwarden_sm
    id: bitwarden-sm-prod
    organization_id: org-abc123-def456
    project_id: proj-ghi789-jkl012
    server_url: https://vault.bitwarden.com
```

Set environment variables:
```bash
export BITWARDEN_SM_ACCESS_TOKEN="your-access-token"
# Optional for self-hosted instances:
export BITWARDEN_SERVER_URL="https://vaultwarden.example.com"
```

**How secrets are retrieved:**
The provider fetches all secrets from the specified project in the organization. Each secret is retrieved using only its Key and Value fields. The Note field is not parsed or used - only the Key-Value pairs are extracted and made available as environment variables.

**Vaultwarden Support:**
The provider works with both official Bitwarden Secret Manager and self-hosted Vaultwarden. Simply set the `server_url` to your Vaultwarden instance URL.

### Choosing Between Bitwarden and Bitwarden Secret Manager

Bitwarden offers two distinct products for secrets management, each designed for different use cases:

**Bitwarden (`bitwarden`) - Personal Vault:**
- **Purpose**: Individual password and secrets management
- **Use Case**: Personal vault items, individual developer secrets, or small-scale secret storage
- **Access Method**: Uses Bitwarden CLI (`bw`) with personal account credentials
- **Authentication**: Requires API client ID/secret and master password
- **Organization**: Items stored in personal vault, organized by folders and collections
- **Access Control**: Single-user access (your personal vault)
- **Best For**: Individual developers, personal projects, or when you need to access your personal Bitwarden vault items

**Bitwarden Secret Manager (`bitwarden_sm`) - Organizational Secrets:**
- **Purpose**: Enterprise secrets management for DevOps and cybersecurity teams
- **Use Case**: Organizational secrets, CI/CD pipelines, infrastructure secrets, team collaboration
- **Access Method**: Uses Bitwarden SDK with machine accounts and access tokens
- **Authentication**: Requires access token (generated for machine accounts)
- **Organization**: Secrets organized in Projects within an Organization
- **Access Control**: Multi-user, role-based access with fine-grained permissions
- **Best For**: Teams, organizations, production deployments, automated systems, and when you need centralized secret management with access control

**Key Differences:**
- **Bitwarden** is part of the Password Manager product and uses the CLI to access personal vault items
- **Bitwarden Secret Manager** is a separate product designed for organizational secrets management with Projects, Machine Accounts, and Access Tokens (see [Bitwarden Secrets Manager Overview](https://bitwarden.com/help/secrets-manager-overview/))
- **Bitwarden** requires the CLI to be installed and uses `bw serve` for local API access
- **Bitwarden Secret Manager** uses the SDK directly and doesn't require CLI installation
- **Bitwarden** stores items in your personal vault (passwords, secure notes, etc.)
- **Bitwarden Secret Manager** stores secrets in organizational projects with structured key-value pairs

**When to use each:**
- Use `bitwarden` if you're working with your personal Bitwarden vault and need to retrieve Secure Note items (with JSON notes or custom fields)
- Use `bitwarden_sm` if you're part of an organization using Bitwarden Secret Manager and need to retrieve secrets from organizational projects (like API keys for production deployments)

## Template Variables

You can use template variables in paths and other configuration values:

```yaml
providers:
  - kind: aws_secretsmanager
    id: env
    secret_id: myapp/{{ get_env(name="ENVIRONMENT", default="development") }}
```

You can also use simple environment variable expansion with `${VAR}` or `$VAR` syntax:
```yaml
  - kind: dotenv
    id: shared
    path: ${HOME}/.config/myapp/.env
```

## Template Providers

The template provider allows you to construct new secrets by combining values from other providers using Go template syntax. This is useful when your application needs secrets in a different format than how they're stored (e.g., building connection URIs from separate credentials).

**Configuration:**
- `uses` (required): List of provider IDs that this template provider depends on. The template provider can only access secrets from providers explicitly listed here (principle of least privilege).
- `templates` (required): Map of output secret keys to template expressions. Each template expression is evaluated using Go's `text/template` package.

**Template Syntax:**
- Use `{{.<provider_id>.<secret_key>}}` to reference secrets from other providers
- The syntax is similar to Helm templates and uses Go's text/template package
- You can use all Go template functions (e.g., `{{if}}`, `{{range}}`, `{{index}}`, etc.)
- Provider IDs and secret keys are case-sensitive

**Security Model:**
The template provider follows the principle of least privilege:
- Only providers listed in the `uses` field are accessible
- If a provider is not in `uses`, references to it will resolve to empty values
- This ensures templates can only access secrets they explicitly declare as dependencies

**Provider Order:**
Template providers must be defined after the providers they depend on. Providers are processed in the order they appear in the configuration file, so ensure all source providers are listed before the template provider.

**Example - Building a Database URI:**
```yaml
providers:
  # Fetch database host configuration
  - kind: aws_secretsmanager
    id: db_config
    secret_id: rds/credentials
    # Returns: DB_HOST, DB_PORT, DB_NAME
  
  # Fetch database credentials
  - kind: aws_secretsmanager
    id: db_creds
    secret_id: rds/prod/credentials
    # Returns: DB_USER, DB_PASSWORD
  
  # Build database URI using template provider
  - kind: template
    uses:
      - db_config
      - db_creds
    templates:
      DATABASE_URI: postgresql://{{.db_creds.DB_USER}}:{{.db_creds.DB_PASSWORD}}@{{.db_config.DB_HOST}}:{{.db_config.DB_PORT}}/{{.db_config.DB_NAME}}
```

**Example - Multiple Templates:**
```yaml
providers:
  - kind: aws_secretsmanager
    id: api_config
    secret_id: api/config
    # Returns: API_HOST, API_PORT
  
  - kind: aws_secretsmanager
    id: api_creds
    secret_id: api/credentials
    # Returns: API_KEY, API_SECRET
  
  - kind: template
    uses:
      - api_config
      - api_creds
    templates:
      API_BASE_URL: https://{{.api_config.API_HOST}}:{{.api_config.API_PORT}}
      API_AUTH_HEADER: Bearer {{.api_creds.API_KEY}}
      API_FULL_URL: https://{{.api_config.API_HOST}}:{{.api_config.API_PORT}}/v1?key={{.api_creds.API_KEY}}
```

**Example - Using Template Functions:**
```yaml
providers:
  - kind: aws_secretsmanager
    id: config
    secret_id: app/config
    # Returns: ENV (e.g., "production")
  
  - kind: template
    uses:
      - config
    templates:
      # Use conditional logic based on secret values
      LOG_LEVEL: {{if eq .config.ENV "production"}}error{{else}}debug{{end}}
      # Combine multiple template expressions
      APP_ENV: {{.config.ENV}}
```

**Error Handling:**
- If a referenced provider ID doesn't exist, the template will fail with an error
- If a referenced secret key doesn't exist in a provider, it will resolve to an empty value
- If `uses` is not specified or empty, all provider references will resolve to empty values
- Template parsing errors will be reported with the specific template expression that failed

## Multiple Providers

Each provider loads from a single source. To load multiple secrets from the same provider type, create multiple provider instances:

```yaml
providers:
  # First AWS Secrets Manager provider - production
  - kind: aws_secretsmanager
    id: aws-prod  # Explicit ID required because there are multiple providers of this kind
    secret_id: myapp/production
  
  # Second AWS Secrets Manager provider - staging
  - kind: aws_secretsmanager
    id: aws-staging  # Explicit ID required because there are multiple providers of this kind
    secret_id: myapp/staging
  
  # Azure Key Vault provider
  - kind: azure_keyvault
    id: azure-prod
    vault_url: https://myvault.vault.azure.net/
    secret_name: myapp/production
  
  - kind: dotenv
    # ID not specified - defaults to 'dotenv'
    path: .env.local
  
  - kind: aws_secretsmanager
    id: shared-aws  # Explicit ID required because there are multiple providers of this kind
    secret_id: shared/secrets
```

When multiple providers share the same `kind`, each must have an explicit, unique `id`. Otherwise, `id` defaults to the `kind` value. Use the `id` values with the `--providers` flag:

```bash
sstart run --providers aws-prod,azure-prod -- node app.js
```

## Key Mappings

The `keys` field allows you to map source keys to target environment variable names:

```yaml
keys:
  SOURCE_KEY: TARGET_KEY    # Map SOURCE_KEY to TARGET_KEY
  ANOTHER_KEY: ==           # Keep the same name (== means keep same name)
```

- If `keys` is empty or not specified, all keys from the secret will be mapped
- If `keys` is specified, only the keys listed will be mapped
- Use `==` to keep the source key name as the target name
- Keys are case-sensitive

## Environment Inheritance

By default, sstart inherits all system environment variables and adds secrets on top. To create a clean environment with only secrets (no system environment variables), set `inherit: false`:

```yaml
inherit: false  # Only use secrets from providers, don't inherit system environment variables

providers:
  - kind: aws_secretsmanager
    secret_id: myapp/production
```

This is useful for ensuring a clean, reproducible environment in CI/CD pipelines or when you want to guarantee that only explicitly configured secrets are available.

## SSO Authentication

sstart supports OIDC-based Single Sign-On for authenticating with secret providers. When SSO is configured, sstart automatically initiates an authentication flow before fetching secrets.

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
    path: secret/myapp
```

The SSO access token is made available to providers for authentication but is NOT injected into subprocess environment variables.

For complete SSO configuration options, authentication flows, and provider integration details, see [SSO.md](SSO.md).

