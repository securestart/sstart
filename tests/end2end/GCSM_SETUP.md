# Google Cloud Secret Manager (GCSM) Testing Setup

This guide explains how to configure credentials for testing the GCSM provider with the real Google Cloud Secret Manager API.

## Local Testing

### Option 1: Using Service Account Key File (Recommended for CI/CD)

1. **Create a Service Account** in your GCP project:
   ```bash
   gcloud iam service-accounts create sstart-test \
     --display-name="sstart test service account"
   ```

2. **Grant Secret Manager permissions**:
   ```bash
   # Grant secret accessor role (required for reading secrets)
   gcloud projects add-iam-policy-binding sstart-ci \
     --member="serviceAccount:sstart-test@sstart-ci.iam.gserviceaccount.com" \
     --role="roles/secretmanager.secretAccessor"
   ```
   
   **Note**: Use the Project ID (`sstart-ci`), not the Project Number. Both work, but Project ID is preferred.
   
   **Note**: For tests, you only need `secretAccessor` role. The `secretVersionManager` role alone is not sufficient - it doesn't grant read access to secret data.

3. **Create and download a key**:
   ```bash
   gcloud iam service-accounts keys create ~/sstart-test-key.json \
     --iam-account=sstart-test@sstart-ci.iam.gserviceaccount.com
   ```

4. **Set environment variables**:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=~/sstart-test-key.json
   export GCP_PROJECT_ID=sstart-ci
   ```

5. **Run tests**:
   ```bash
   go test -v ./tests/end2end -run TestE2E_Testcontainers_GCSM
   ```

### Option 2: Using gcloud Application Default Credentials

1. **Authenticate with gcloud**:
   ```bash
   gcloud auth application-default login
   ```

2. **Set project ID**:
   ```bash
   export GCP_PROJECT_ID=YOUR_PROJECT_ID
   ```

3. **Run tests**:
   ```bash
   go test -v ./tests/end2end -run TestE2E_Testcontainers_GCSM
   ```

## GitHub Actions Setup

1. **Create a Service Account** (same as local setup above)

2. **Create and download the service account key** (JSON format)

3. **Add GitHub Secrets**:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Add the following secrets:
     - `GCP_SA_KEY`: The entire contents of the service account JSON key file
     - `GCP_PROJECT_ID`: Your GCP project ID

4. **The CI workflow is already configured** to use these secrets:
   ```yaml
   - name: Authenticate to Google Cloud
     uses: google-github-actions/auth@v2
     with:
       credentials_json: ${{ secrets.GCP_SA_KEY }}
   
   - name: Set up Cloud SDK
     uses: google-github-actions/setup-gcloud@v2
   
   - name: Run end-to-end tests
     env:
       GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
     run: go test -v ./tests/end2end/...
   ```

## Pre-creating Test Secrets

Tests use **predefined secrets** that must be created beforehand. This approach:
- Reduces required permissions (only read access needed)
- Makes tests faster (no create/delete overhead)
- Provides a more predictable test environment

### Create the Test Secret

The test secret is already created at: `projects/sstart-ci/secrets/test-ci`
   
**Note**: You can use either the Project ID (`sstart-ci`) or Project Number (`539938803546`) - both work in API calls.

If you need to recreate it or create it in a different project:

1. **Create a JSON file with test data**:
   ```bash
   cat > /tmp/test-ci-secret.json <<EOF
   {"foo":"bar"}
   EOF
   ```

2. **Create the secret in GCP**:
   ```bash
   gcloud secrets create test-ci \
     --project=sstart-ci \
     --replication-policy="automatic"
   ```

3. **Add the secret version**:
   ```bash
   gcloud secrets versions add test-ci \
     --project=sstart-ci \
     --data-file=/tmp/test-ci-secret.json
   ```

4. **Verify the secret exists**:
   ```bash
   gcloud secrets versions access latest \
     --secret=test-ci \
     --project=sstart-ci
   ```

### Secret Name

The tests expect a secret named: **`test-ci`**

The secret should be located at: `projects/sstart-ci/secrets/test-ci`
   
**Note**: Both Project ID (`sstart-ci`) and Project Number (`539938803546`) work in API calls, but Project ID is preferred.

The secret content should be: `{"foo":"bar"}`

If you need to use a different secret, you can set it via environment variable:
```bash
export GCSM_TEST_SECRET_ID=your-custom-secret-name
export GCP_PROJECT_ID=your-project-id
```

## Required Permissions

Since tests only **read** from predefined secrets, the service account needs:
- `roles/secretmanager.secretAccessor` - **Required** - Read access to secret data

**Important**: The `roles/secretmanager.secretVersionManager` role alone is **not sufficient**. While it allows managing secret versions (adding/deleting), it does **not** grant permission to read/access the secret data itself. You must also grant `roles/secretmanager.secretAccessor` to read secrets.

### Granting the Correct Permissions

```bash
# Grant secret accessor role (required for reading secrets)
gcloud projects add-iam-policy-binding sstart-ci \
  --member="serviceAccount:YOUR_SERVICE_ACCOUNT@sstart-ci.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Optional: If you also need to manage versions
gcloud projects add-iam-policy-binding sstart-ci \
  --member="serviceAccount:YOUR_SERVICE_ACCOUNT@sstart-ci.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretVersionManager"
```

**Note**: You'll need admin permissions to create the secret initially, but the test service account only needs `secretAccessor` for running tests.

## Test Behavior

- Tests will **skip** if `GCP_PROJECT_ID` is not set
- Tests will **skip** if the predefined secret doesn't exist (graceful handling)
- Tests will **fail** if credentials are not configured or invalid
- Tests **do not** create or delete secrets (read-only)

## Troubleshooting

### "Failed to create GCSM client"
- Verify `GOOGLE_APPLICATION_CREDENTIALS` points to a valid key file
- Or ensure `gcloud auth application-default login` was run
- Check that the service account has the required permissions

### "Permission denied" errors
- **Most common issue**: You have `roles/secretmanager.secretVersionManager` but not `roles/secretmanager.secretAccessor`
  - `secretVersionManager` can manage versions but **cannot read** secret data
  - You **must** also grant `roles/secretmanager.secretAccessor` to read secrets
- Ensure the service account has `roles/secretmanager.secretAccessor` role
- Verify the project ID is correct
- Verify the secret exists and is accessible
- Check IAM policy: `gcloud projects get-iam-policy sstart-ci --flatten="bindings[].members" --filter="bindings.members:YOUR_SERVICE_ACCOUNT"`

### Tests are skipped
- Check that `GCP_PROJECT_ID` environment variable is set (default: `sstart-ci`)
- Verify the secret `test-ci` exists in your project
- Tests will skip if credentials are not available (this is expected behavior)
- Tests will skip if the secret doesn't exist (see "Pre-creating Test Secrets" above)

### "Secret does not exist" skip message
- The secret should be at: `projects/sstart-ci/secrets/test-ci`
- Verify the secret name matches exactly: `test-ci`
- Check that the secret has at least one version
- The secret content should be: `{"foo":"bar"}`
- **Note**: You can use either Project ID (`sstart-ci`) or Project Number (`539938803546`) - both work

