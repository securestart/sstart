# sstart Usage Showcase

This directory contains examples demonstrating how to use the `sstart` binary with various configuration scenarios.

## Prerequisites

1. Install the `sstart` binary using one of the following methods:

   **Option 1: Install from GitHub Releases (Recommended)**
   
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

   **Windows:**
   ```powershell
   # Download and extract from https://github.com/dirathea/sstart/releases/latest
   # Add sstart.exe to your PATH
   ```

   **Option 2: Install via Go**
   ```bash
   go install github.com/dirathea/sstart/cmd/sstart@latest
   ```

   **Option 3: Build from Source**
   ```bash
   # From the repository root
   go build -o sstart ./cmd/sstart
   # Or install globally:
   go install ./cmd/sstart
   ```

   **Note:** If you prefer to use a local binary (e.g., in the `examples/` directory), you can download or build the binary and reference it with `./sstart` instead of `sstart` in the examples below.

2. Make sure the Python script is executable:
   ```bash
   chmod +x show_env.py
   ```

## Examples

### 1. Basic Usage

**Configuration:** `.sstart.yml.basic`

This is the simplest example showing how to load secrets from a `.env` file.

```bash
# Copy the basic config
cp .sstart.yml.basic .sstart.yml

# Run the Python script with sstart
sstart run -- python3 show_env.py
```

**What it demonstrates:**
- Basic dotenv provider configuration
- Default `inherit: true` behavior (system env vars are also available)
- Key mapping with `==` to keep the same name

**Expected output:**
- `API_KEY` from `.env.basic`
- `DATABASE_URL` from `.env.basic`
- `APP_NAME` from `.env.basic`
- Plus all system environment variables

---

### 2. Inherit False

**Configuration:** `.sstart.yml.inherit-false`

This example shows how to create a clean environment with ONLY secrets from providers.

```bash
# Copy the inherit-false config
cp .sstart.yml.inherit-false .sstart.yml

# Run the Python script
sstart run -- python3 show_env.py
```

**What it demonstrates:**
- Using `inherit: false` to exclude system environment variables
- Clean, reproducible environment with only explicitly configured secrets

**Expected output:**
- Only `API_KEY`, `DATABASE_URL`, and `APP_NAME` from `.env.basic`
- No system environment variables (except minimal ones required by the OS)

---

### 3. Overrides

**Configuration:** `.sstart.yml.overrides`

This example demonstrates how multiple providers can override each other, with later providers taking precedence.

```bash
# Copy the overrides config
cp .sstart.yml.overrides .sstart.yml

# Run the Python script
sstart run -- python3 show_env.py
```

**What it demonstrates:**
- Multiple providers with the same `kind` (requires explicit `id` fields)
- Provider order matters - later providers override earlier ones
- Combining secrets from multiple sources

**Expected output:**
- `API_KEY` from `.env.override` (overrides the one from `.env.basic`)
- `DATABASE_URL` from `.env.basic` (not overridden)
- `APP_NAME` from `.env.basic` (not overridden)
- `SECRET_TOKEN` from `.env.override` (new variable)
- `ENVIRONMENT` from `.env.override` (new variable)

---

### 4. Key Mapping

**Configuration:** `.sstart.yml.key-mapping`

This example shows how to map source keys to different target environment variable names.

```bash
# Copy the key-mapping config
cp .sstart.yml.key-mapping .sstart.yml

# Run the Python script
sstart run -- python3 show_env.py
```

**What it demonstrates:**
- Renaming environment variables during the mapping process
- Using `==` to keep the same name vs. specifying a new name

**Expected output:**
- `API_SECRET_KEY` (mapped from `API_KEY`)
- `DB_CONNECTION_STRING` (mapped from `DATABASE_URL`)
- `APP_NAME` (kept as is with `==`)

---

## Testing All Examples

You can quickly test all examples with this script:

```bash
#!/bin/bash
for config in .sstart.yml.basic .sstart.yml.inherit-false .sstart.yml.overrides .sstart.yml.key-mapping; do
    echo "=========================================="
    echo "Testing: $config"
    echo "=========================================="
    cp "$config" .sstart.yml
    sstart run -- python3 show_env.py
    echo ""
    echo ""
done
```

## Notes

- The `.env.basic` and `.env.override` files contain sample secrets for demonstration purposes
- In production, never commit `.env` files or `.sstart.yml` files with real secrets to version control
- The Python script masks secret values for security when displaying them
- You can use `sstart show` to preview what secrets will be loaded without running a command:
  ```bash
  sstart show
  ```

## Next Steps

- Try combining different provider types (AWS Secrets Manager, Azure Key Vault, etc.)
- Experiment with the `--providers` flag to selectively use specific providers
- Check the main [CONFIGURATION.md](../CONFIGURATION.md) for advanced features

