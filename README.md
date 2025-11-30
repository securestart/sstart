# 🤫 sstart: Secure Start for Cloud-Native Secrets
sstart is a minimalist, zero-persistence CLI tool that securely retrieves application secrets from multiple backend sources (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) and injects them as environment variables into any wrapped process.

It is the spiritual successor to the [Teller](https://github.com/tellerops/teller), modernized and rebuilt in Go for fast execution, reliability, and cross-platform simplicity.

## 🎯 The Problem sstart Solves
For local development, teams often choose between two bad options:

1. Static .env files: Highly insecure, prone to being committed to Git, and impossible to audit.

2. Custom scripts: Complex, unmaintainable shell scripts that only talk to one vault and are difficult to standardize across projects.

sstart eliminates both. You define all your required secrets from all your sources (e.g., database password from Vault, API key from AWS) in a single, declarative .sstart.yml file.

## Features

- 🔐 **Multiple Secret Providers**: Support for AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, GCP Secret Manager, dotenv files, and more
- 🔄 **Combine Secrets**: Merge secrets from multiple providers
- 🚀 **Subprocess Execution**: Automatically inject secrets into subprocesses
- 🔒 **Secure by Default**: Secrets never appear in shell history or logs
- ⚙️ **YAML Configuration**: Easy-to-use configuration file

## Installation

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


## Security

- Secrets are never logged or displayed in full
- Use `inherit: false` in your config to ensure a clean environment (only secrets, no system env vars)
- Secrets are injected directly into subprocess environment, never exposed to shell
- Configuration files should be added to `.gitignore`

## License

Apache-2.0

