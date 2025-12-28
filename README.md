# 🤫 sstart: Secure Start for Cloud-Native Secrets
sstart is a minimalist, zero-persistence CLI tool that securely retrieves application secrets from multiple backend sources (1Password, Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) and injects them as environment variables into any wrapped process.

It is the spiritual successor to the [Teller](https://github.com/tellerops/teller), modernized and rebuilt in Go for fast execution, reliability, and cross-platform simplicity.

## 🎯 Why sstart?

Say goodbye to `.env` files. With sstart, we eliminate the need for static `.env` files that store secrets in your project directory. Instead, secrets are pulled at runtime from secure backends like 1Password, AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, or GCP Secret Manager.

This approach provides multiple security benefits:

**🔒 Enhanced Security**: No more secrets sitting in files that could be accidentally committed to Git, shared in screenshots, or exposed through other common developer mistakes. Secrets are retrieved only when needed, directly from secure vaults.

**🤖 AI Agent Protection**: In the era of AI-assisted coding, this is crucial. Static `.env` files expose secrets to AI agents that read project files during development. These secrets can be inadvertently included in prompts, code reviews, or context windows, creating a significant security vulnerability. With sstart, secrets are pulled at runtime and never stored in files that AI agents can access—only the configuration structure (`.sstart.yml`) is exposed, keeping your actual secrets safe.

You define all your required secrets from all your sources in a single, declarative `.sstart.yml` file, and sstart handles the rest securely.

## Features

- 🔐 **Multiple Secret Providers**: Support for 1Password, AWS Secrets Manager, Azure Key Vault, Bitwarden, Doppler, HashiCorp Vault, GCP Secret Manager, dotenv files, and more
- 🔄 **Combine Secrets**: Merge secrets from multiple providers
- 🧩 **Template Providers**: Construct new secrets by combining values from other providers using Go template syntax (e.g., build database URIs from separate credentials)
- 🚀 **Subprocess Execution**: Automatically inject secrets into subprocesses
- 🔒 **Secure by Default**: Secrets never appear in shell history or logs
- ⚙️ **YAML Configuration**: Easy-to-use configuration file

## Installation

### Install from GitHub Releases (Recommended)

Download the pre-built binary for your platform from the [latest release](https://github.com/dirathea/sstart/releases/latest):

**Linux (amd64):**
```bash
curl -L https://github.com/dirathea/sstart/releases/latest/download/sstart_Linux_x86_64.tar.gz | tar -xz
sudo mv sstart /usr/local/bin/
```

**macOS (amd64):**
```bash
curl -L https://github.com/dirathea/sstart/releases/latest/download/sstart_Darwin_x86_64.tar.gz | tar -xz
sudo mv sstart /usr/local/bin/
```

**macOS (Apple Silicon/arm64):**
```bash
curl -L https://github.com/dirathea/sstart/releases/latest/download/sstart_Darwin_arm64.tar.gz | tar -xz
sudo mv sstart /usr/local/bin/
```

**Using a specific version:**
Replace `latest` with a version tag (e.g., `v1.0.0`) in the URLs above.

### Install via Go

```bash
go install github.com/dirathea/sstart/cmd/sstart@latest
```

## Quick Start

1. Create a `.sstart.yml` configuration file:

```yaml
providers:
  - kind: aws_secretsmanager
    id: prod
    secret_id: myapp/production
    keys:
      API_KEY: ==
      DATABASE_URL: ==
  
  - kind: dotenv
    id: dev
    path: .env.local
```

2. Run a command with secrets injected:

```bash
sstart run -- node index.js
```

## Commands

### `sstart run`

Run a command with injected secrets:

```bash
sstart run -- node index.js
sstart run --providers aws-prod,dotenv-dev -- python app.py
```

Flags:
- `--providers`: Comma-separated list of provider IDs to use (default: all providers)
- `--config, -c`: Path to configuration file (default: `.sstart.yml`)

### `sstart show`

Show collected secrets (masked for security):

```bash
sstart show
sstart show --providers aws-prod,dotenv-dev
```

Flags:
- `--providers`: Comma-separated list of provider IDs to use (default: all providers)

### `sstart env`

Export secrets in environment variable format:

```bash
# Shell format
sstart env

# JSON format
sstart env --format json

# YAML format
sstart env --format yaml

# Docker usage
docker run --env-file <(sstart env) alpine sh

# Use specific providers
sstart env --providers aws-prod,dotenv-dev
```

Flags:
- `--format`: Output format: `shell` (default), `json`, or `yaml`
- `--providers`: Comma-separated list of provider IDs to use (default: all providers)

### `sstart sh`

Generate shell commands to export secrets:

```bash
eval "$(sstart sh)"
source <(sstart sh)
```

Flags:
- `--providers`: Comma-separated list of provider IDs to use (default: all providers)

## Configuration

See [CONFIGURATION.md](CONFIGURATION.md) for complete configuration documentation, including:

- Configuration file structure
- All supported providers and their options
- Authentication methods
- Template providers for constructing secrets from other providers
- Template variables
- Multiple provider setup
- Key mappings

## Examples

### Using with Node.js

```bash
sstart run -- node index.js
```

### Using with Docker

```bash
docker run --rm -it --env-file <(sstart env) node:18-alpine sh
```

### Using Template Providers

Construct new secrets by combining values from other providers:

```yaml
providers:
  # Fetch database credentials from AWS Secrets Manager
  - kind: aws_secretsmanager
    id: db_creds
    secret_id: rds/prod/credentials
  
  # Fetch database host from another source
  - kind: aws_secretsmanager
    id: db_config
    secret_id: rds/config
  
  # Build database URI using template provider
  - kind: template
    uses:
      - db_creds
      - db_config
    templates:
      DATABASE_URI: postgresql://{{.db_creds.DB_USER}}:{{.db_creds.DB_PASSWORD}}@{{.db_config.DB_HOST}}:{{.db_config.DB_PORT}}/{{.db_config.DB_NAME}}
```

Template syntax uses `{{.<provider_id>.<secret_key>}}` notation (similar to Helm templates). See [CONFIGURATION.md](CONFIGURATION.md) for more details.


## Security

- Secrets are never logged or displayed in full
- Use `inherit: false` in your config to ensure a clean environment (only secrets, no system env vars)
- Secrets are injected directly into subprocess environment, never exposed to shell
- Configuration files should be added to `.gitignore`

## License

Apache-2.0

