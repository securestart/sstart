# Configuration

The `.sstart.yml` file defines your providers and secret mappings.

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
| `aws_secretsmanager` | Stable |
| `azure_keyvault` | Stable |
| `dotenv` | Stable |
| `gcloud_secretmanager` | Stable |
| `vault` | Stable |

## Provider Configuration

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
    keys:
      API_KEY: ==
      DATABASE_URL: ==
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
    keys:
      API_KEY: AZURE_API_KEY
      DB_PASSWORD: AZURE_DB_PASSWORD
      JWT_SECRET: ==  # Keep same name
```

**JSON Secrets:**
If the secret value in Azure Key Vault is a JSON object, it will be automatically parsed and each key-value pair will be mapped according to the `keys` configuration. If `keys` is empty, all keys from the JSON will be mapped.

**Plain Text Secrets:**
If the secret value is plain text (not JSON), it will be mapped to a single environment variable named `<PROVIDER_ID>_SECRET` (where `<PROVIDER_ID>` is the provider's ID in uppercase, with hyphens converted to underscores). A warning will be logged indicating that the secret is not in JSON format.

For example, if the provider ID is `aws-prod`, the secret will be loaded to `AWS_PROD_SECRET`.

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
    keys:
      LOCAL_API_KEY: API_KEY
      LOCAL_DB_URL: DATABASE_URL
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
    keys:
      API_KEY: ==
      DATABASE_URL: ==
```

**JSON Secrets:**
If the secret value in Google Cloud Secret Manager is a JSON object, it will be automatically parsed and each key-value pair will be mapped according to the `keys` configuration. If `keys` is empty, all keys from the JSON will be mapped.

**Plain Text Secrets:**
If the secret value is plain text (not JSON), it will be mapped to a single environment variable named `<PROVIDER_ID>_SECRET` (where `<PROVIDER_ID>` is the provider's ID in uppercase, with hyphens converted to underscores). A warning will be logged indicating that the secret is not in JSON format.

For example, if the provider ID is `aws-prod`, the secret will be loaded to `AWS_PROD_SECRET`.

### HashiCorp Vault (`vault`)

Retrieves secrets from HashiCorp Vault. Supports both KV v1 and KV v2 secret engines.

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
    keys:
      API_KEY: ==
      DATABASE_URL: ==
```

**KV v1 and v2 Support:**
The provider automatically detects and supports both KV v1 and KV v2 secret engines. For KV v2, the data is automatically extracted from the `data` key.

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

