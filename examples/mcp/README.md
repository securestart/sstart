# MongoDB MCP Demo with sstart + OpenBao

Experience sstart's MCP capabilities with production-like secret management using OpenBao (Vault) and AI-powered data generation!

## 🎯 What This Demonstrates

- **OpenBao (Vault) Secret Management**: Store MongoDB credentials as separate, granular components
- **Template Provider**: Construct connection strings from credential components
- **Secure Secret Injection**: Credentials never exposed to AI models
- **AI-Powered Data Generation**: No custom initialization scripts needed
- **MCP Proxy Pattern**: Single point of access to multiple MCP servers
- **Production-Ready Architecture**: Patterns that scale to real deployments

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose**: For running MongoDB and OpenBao
- **sstart CLI**: Install from [releases](https://github.com/securestart/sstart/releases) or build from source
- **AI Client**: One of:
  - [Claude Desktop](https://claude.ai/download)
  - [VSCode with GitHub Copilot](https://code.visualstudio.com/)
  - [Cursor](https://cursor.sh/)
  - [Windsurf](https://codeium.com/windsurf)

### 5-Minute Setup

#### 1. Start Services

```bash
cd examples/mcp
docker-compose up -d
```

This starts:
- **MongoDB** (port 27017) - Empty database ready for data
- **OpenBao** (port 8200) - Vault for storing credentials in dev mode
- **OpenBao Init** - One-time container that stores MongoDB credentials in Vault

Wait ~10 seconds for initialization to complete.

#### 2. Verify Setup (Optional)

```bash
# Check that OpenBao stored the credentials
docker exec sstart-demo-openbao \
  bao kv get -address=http://localhost:8200 -token=demo-token secret/mongodb
```

Expected output:
```
====== Data ======
Key              Value
---              -----
auth_database    admin
database         demo
host             localhost
password         secret123
port             27017
username         admin
```

#### 3. Start sstart MCP Proxy

```bash
sstart mcp --config .sstart.yml
```

**What happens:**
1. sstart connects to OpenBao at `http://localhost:8200`
2. Authenticates with token `demo-token`
3. Fetches MongoDB credentials (username, password, host, port, database, auth_database)
4. Template provider constructs the MongoDB connection string
5. Starts MongoDB MCP server with injected `MONGODB_URI`
6. Proxies MCP requests between AI client and MongoDB server

#### 4. Configure Your AI Client

Choose your AI client and add the sstart MCP proxy configuration:

**Claude Desktop** - Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sstart-mongodb": {
      "command": "sstart",
      "args": ["mcp", "--config", "/absolute/path/to/examples/mcp/.sstart.yml"]
    }
  }
}
```

**VSCode / GitHub Copilot** - Add to `.vscode/settings.json` or user settings:

```json
{
  "mcp.servers": {
    "sstart-mongodb": {
      "command": "sstart",
      "args": ["mcp", "--config", "/absolute/path/to/examples/mcp/.sstart.yml"]
    }
  }
}
```

**Cursor** - Add to MCP settings:

```json
{
  "sstart-mongodb": {
    "command": "sstart",
    "args": ["mcp", "--config", "/absolute/path/to/examples/mcp/.sstart.yml"]
  }
}
```

**Important**: Replace `/absolute/path/to/` with the actual absolute path to the `examples/mcp/` directory.

#### 5. Generate Sample Data with AI

Now ask your AI assistant to create sample data! Here's a starter prompt:

```
Create a sample e-commerce database in MongoDB with:
- Database name: "demo"
- Collection "products" with 30 products across categories: Electronics, Clothing, Books
  - Fields: name, description, price, category, stock, tags, created_at
- Collection "customers" with 15 customers
  - Fields: name, email, address (city, state), tier (bronze/silver/gold), join_date
- Collection "orders" with 25 orders
  - Fields: customer_id, items (product_id, quantity, price), total, status, order_date

Use realistic data with variety in prices ($10-$2000), dates (last 6 months), 
and product categories.
```

See [sample-prompts.md](./sample-prompts.md) for more prompt examples.

#### 6. Explore with AI

Once data is generated, try these queries:

- "Show me all products priced between $100 and $500"
- "What's the total revenue by month?"
- "List the top 10 customers by total spending"
- "Find products with low stock (under 10 items)"
- "Show average ratings for the Electronics category"

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────┐
│   AI Client         │  (Claude Desktop, VSCode, Cursor)
│   (Your Interface)  │
└──────────┬──────────┘
           │ MCP Protocol (stdio/HTTP)
           ▼
┌────────────────────────────────┐
│   sstart MCP Proxy             │
│                                │
│   1. Fetch Credentials         │──────┐
│      from OpenBao              │      │
│                                │      │
│   2. Template Provider         │      │
│      Constructs Connection     │      │
│      String                    │      │
│                                │      ▼
│   3. Inject MONGODB_URI        │  ┌──────────────┐
│      into MCP Server           │  │   OpenBao    │
└────────────┬───────────────────┘  │   (Vault)    │
             │                      │              │
             │ Namespaced Tools     │  Stores:     │
             │ (mongodb/find,       │  - username  │
             │  mongodb/aggregate)  │  - password  │
             │                      │  - host      │
             ▼                      │  - port      │
┌──────────────────────────┐       │  - database  │
│  MongoDB MCP Server      │       │  - auth_db   │
│  (Docker Container)      │       └──────────────┘
│                          │
│  Receives:               │
│  MDB_MCP_CONNECTION_     │
│  STRING=mongodb://...    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│      MongoDB 7           │
│   (Docker Container)     │
│                          │
│   Collections:           │
│   - products (empty)     │
│   - customers (empty)    │
│   - orders (empty)       │
│   → AI populates data!   │
└──────────────────────────┘
```

### Secret Flow Diagram

```
1. OpenBao Storage (Granular Components)
   └─ secret/mongodb
      ├─ username: "admin"
      ├─ password: "secret123"
      ├─ host: "localhost"
      ├─ port: "27017"
      ├─ database: "demo"
      └─ auth_database: "admin"

2. Vault Provider Fetch (No Remapping)
   └─ Environment Variables:
      ├─ username=admin
      ├─ password=secret123
      ├─ host=localhost
      ├─ port=27017
      ├─ database=demo
      └─ auth_database=admin

3. Template Provider Construction
   └─ MONGODB_URI=mongodb://admin:secret123@localhost:27017/demo?authSource=admin
      Using template:
      mongodb://{{.mongodb-creds.username}}:{{.mongodb-creds.password}}@...

4. sstart Injection
   └─ MDB_MCP_CONNECTION_STRING → MongoDB MCP Server
      (Connection string injected as environment variable)

5. MongoDB MCP Server
   └─ Connects to MongoDB using the injected connection string
      AI never sees the credentials!
```

---

## 💡 Understanding the Template Provider

### The Problem

The MongoDB MCP server expects a complete connection string:
```
mongodb://username:password@host:port/database?authSource=admin
```

Storing this as a single string in Vault isn't ideal because:
- ❌ Changing the password requires updating the entire string
- ❌ Different environments need different hosts (dev/staging/prod)
- ❌ Not following security best practices for credential management

### The Solution: Composition Pattern

Instead, we use a **composition pattern** with the template provider:

**Step 1: Store components separately in OpenBao**
```yaml
secret/mongodb:
  username: admin
  password: secret123
  host: localhost
  port: 27017
  database: demo
  auth_database: admin
```

**Step 2: Vault provider fetches components**
```yaml
providers:
  - kind: vault
    id: mongodb-creds
    address: http://localhost:8200
    token: demo-token
    path: secret/data/mongodb
    # No keys mapping - fetches all secrets with original names
```

**Step 3: Template provider constructs the connection string**
```yaml
- kind: template
  uses:
    - mongodb-creds
  templates:
    MONGODB_URI: "mongodb://{{.mongodb-creds.username}}:{{.mongodb-creds.password}}@{{.mongodb-creds.host}}:{{.mongodb-creds.port}}/{{.mongodb-creds.database}}?authSource={{.mongodb-creds.auth_database}}"
```

### Benefits of This Approach

✅ **Easy Rotation**: Change just the password in Vault, no config updates needed  
✅ **Environment Flexibility**: Different host per environment (dev/staging/prod)  
✅ **Granular Control**: Update individual components independently  
✅ **Production Pattern**: Same approach used in real systems  
✅ **Security Best Practice**: Separate credential storage and composition  
✅ **Reusability**: Same credentials can construct different formats if needed  

This pattern is production-ready and scales to complex scenarios.

---

## 🔧 Configuration Details

### Environment Variables Exposed

After sstart processes the configuration, these environment variables are available to the MongoDB MCP server:

From Vault provider (original names):
- `username`
- `password`
- `host`
- `port`
- `database`
- `auth_database`

From Template provider (constructed):
- `MONGODB_URI` (the complete connection string)

The MongoDB MCP server uses `MONGODB_URI` (mapped to `MDB_MCP_CONNECTION_STRING` in the MCP server args).

### Customizing the Configuration

#### Change MongoDB Credentials

Update credentials in OpenBao:
```bash
docker exec sstart-demo-openbao \
  bao kv put -address=http://localhost:8200 -token=demo-token \
  secret/mongodb \
  username="newuser" \
  password="newpass123" \
  host="localhost" \
  port="27017" \
  database="demo" \
  auth_database="admin"
```

Restart sstart MCP proxy - it will fetch the new credentials.

#### Add Connection String Options

Extend the template to include additional MongoDB connection options:

```yaml
templates:
  MONGODB_URI: "mongodb://{{.mongodb-creds.username}}:{{.mongodb-creds.password}}@{{.mongodb-creds.host}}:{{.mongodb-creds.port}}/{{.mongodb-creds.database}}?authSource={{.mongodb-creds.auth_database}}&retryWrites=true&w=majority"
```

First, add the options to Vault storage in `init-openbao.sh`.

#### Enable Read-Only Mode

To allow AI to only read data (no writes):

```yaml
mcp:
  servers:
    - id: mongodb
      command: docker
      args:
        - run
        - --rm
        - -i
        - --network=host
        - -e
        - MDB_MCP_CONNECTION_STRING
        - -e
        - MDB_MCP_READ_ONLY=true  # Add this line
        - mcp/mongodb:latest
```

---

## 🐛 Troubleshooting

### Services Won't Start

```bash
# Check all services
docker-compose ps

# Should show:
# - sstart-demo-mongodb (healthy)
# - sstart-demo-openbao (healthy)
# - sstart-demo-openbao-init (exited 0)
```

View logs if there are issues:
```bash
docker-compose logs mongodb
docker-compose logs openbao
docker-compose logs openbao-init
```

### OpenBao Not Initialized

```bash
# Check if secret exists
docker exec sstart-demo-openbao \
  bao kv get -address=http://localhost:8200 -token=demo-token secret/mongodb

# If not found, re-run initialization
docker-compose restart openbao-init
docker-compose logs openbao-init
```

### sstart Can't Connect to Vault

```bash
# Test OpenBao connectivity
curl http://localhost:8200/v1/sys/health

# Should return: {"initialized":true,"sealed":false,...}

# Verify secret is accessible
curl -H "X-Vault-Token: demo-token" \
  http://localhost:8200/v1/secret/data/mongodb
```

### MongoDB Connection Failed

```bash
# Test MongoDB directly
mongosh "mongodb://admin:secret123@localhost:27017/demo?authSource=admin"

# Check MongoDB is healthy
docker exec sstart-demo-mongodb mongosh --eval "db.runCommand('ping')"

# Should return: { ok: 1 }
```

### MongoDB MCP Server Network Issues

**On Linux**: `--network=host` works fine.

**On macOS/Windows**: Docker's `host` networking doesn't work the same way.

**Solution for Mac/Windows**: Use `host.docker.internal`:

1. Update `init-openbao.sh`:
   ```bash
   bao kv put secret/mongodb \
     username="admin" \
     password="secret123" \
     host="host.docker.internal" \  # Changed
     port="27017" \
     database="demo" \
     auth_database="admin"
   ```

2. Or update manually:
   ```bash
   docker exec sstart-demo-openbao \
     bao kv patch -address=http://localhost:8200 -token=demo-token \
     secret/mongodb host="host.docker.internal"
   ```

### AI Client Doesn't See MCP Tools

- **Restart AI client** after adding configuration
- **Check sstart is running**: `ps aux | grep sstart`
- **Verify paths are absolute**: Relative paths won't work in AI client configs
- **Check logs**: sstart outputs to stderr, your AI client may show MCP logs

### Template Provider Errors

If you see template errors, verify:
```bash
# Test sstart configuration
sstart show --config .sstart.yml

# Should show all environment variables including MONGODB_URI
```

Common issues:
- Provider ID mismatch in `uses:` field
- Typo in template variable names
- Missing provider (ensure vault provider is before template provider)

---

## 🔒 Security Features

### What This Demo Shows

✅ **Centralized Secret Storage**: Credentials stored in OpenBao, not config files or environment  
✅ **Granular Credential Management**: Separate username, password, host, etc.  
✅ **Secure Injection**: sstart fetches secrets and injects at runtime  
✅ **Zero Credential Exposure to AI**: Connection string never sent to AI models  
✅ **Template Composition**: Build complex strings from simple components  
✅ **Production-Ready Pattern**: Architecture scales to real deployments  

### Dev Mode vs Production

This demo uses **dev mode** for simplicity:

| Aspect | Demo (Dev Mode) | Production |
|--------|-----------------|------------|
| **Token** | Static `demo-token` | Dynamic, short-lived tokens (AppRole, JWT, K8s) |
| **Storage** | In-memory (lost on restart) | Persistent, encrypted backend (Consul, etcd, S3) |
| **Network** | HTTP (localhost) | HTTPS with TLS certificates |
| **Auth** | Token auth | AppRole, JWT, Kubernetes auth, OIDC |
| **HA** | Single instance | Multi-node cluster with raft consensus |
| **Audit** | None | Full audit logging to files/syslog |
| **Policies** | Root token (full access) | Fine-grained policies (least privilege) |

### Production Migration

For production deployment, update `.sstart.yml`:

```yaml
providers:
  - kind: vault
    id: mongodb-creds
    address: https://vault.production.example.com  # HTTPS
    # Use AppRole instead of static token
    # Token will be provided via environment variable or SSO
    path: secret/data/mongodb/production

  # ... rest of config
```

Set up proper Vault authentication:
- Use AppRole for service accounts
- Use JWT/OIDC for user authentication
- Use Kubernetes auth when running in K8s
- Enable audit logging and monitoring
- Configure secret rotation policies

See [SSO.md](../../SSO.md) for OIDC authentication setup.

---

## 📚 Learn More

### Documentation

- [sstart Documentation](../../README.md)
- [sstart Configuration Guide](../../CONFIGURATION.md)
- [sstart Template Provider](../../CONFIGURATION.md#template-providers)
- [sstart MCP Proxy](../../README.md#mcp-proxy)
- [sstart SSO Configuration](../../SSO.md)

### External Resources

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [MongoDB MCP Server](https://github.com/mongodb-js/mongodb-mcp-server)
- [OpenBao Documentation](https://openbao.org/docs/)
- [HashiCorp Vault](https://www.vaultproject.io/) (API-compatible with OpenBao)

---

## 🎓 Next Steps

### After Completing This Demo

1. **Try Different Data Domains**
   - Generate blog platform data
   - Create IoT sensor data
   - Build inventory management data
   - See [sample-prompts.md](./sample-prompts.md) for ideas

2. **Enable Read-Only Mode**
   - Add `MDB_MCP_READ_ONLY=true` to safely explore data
   - Prevent accidental modifications

3. **Add More MCP Servers**
   - Add filesystem server for reading documents
   - Add weather API server
   - Add custom API servers
   - Demonstrate multi-server proxy

4. **Try Different Secret Providers**
   - Use AWS Secrets Manager instead of Vault
   - Use 1Password for credentials
   - Use Azure Key Vault
   - Compare provider experiences

5. **Explore Production Patterns**
   - Set up real Vault cluster (not dev mode)
   - Configure AppRole authentication
   - Enable secret rotation
   - Add audit logging

6. **Build Your Own Demo**
   - Point to your actual MongoDB instance
   - Use your production Vault
   - Add your custom MCP servers
   - Integrate with your workflow

---

## 🌟 Why This Demo Matters

### Traditional Approach Problems

❌ Secrets in `.env` files (checked into git accidentally)  
❌ Hardcoded credentials in config files  
❌ Manual secret distribution to team members  
❌ No audit trail of who accessed secrets  
❌ Difficult to rotate credentials  
❌ Credentials exposed in process environment  

### This Demo's Approach

✅ **Centralized Secret Management**: All credentials in Vault  
✅ **Automated Distribution**: sstart fetches secrets automatically  
✅ **Audit Trail**: Vault logs all access (in production)  
✅ **Easy Rotation**: Update password in Vault, restart services  
✅ **Secure Injection**: Credentials never in config files or git  
✅ **AI Safety**: AI never sees credentials  

### Real-World Impact

This demo shows patterns used by:
- Fortune 500 companies
- Modern cloud-native applications
- DevOps teams managing secrets at scale
- Security-conscious organizations

The architecture scales from this demo (1 service, 1 secret) to production (hundreds of services, thousands of secrets) without fundamental changes.

---

## 📝 Feedback & Contributions

Found an issue or have a suggestion? Please open an issue or PR at:
https://github.com/securestart/sstart

---

**Happy Secret Managing! 🔐**
