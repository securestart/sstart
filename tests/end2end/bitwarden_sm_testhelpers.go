package end2end

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bitwarden/sdk-go"
)

// BitwardenSMTestSetup contains the test setup for Bitwarden Secret Manager
type BitwardenSMTestSetup struct {
	OrganizationID string
	ProjectID      string
	Client         sdk.BitwardenClientInterface
	Cleanup        func() error
}

// SetupBitwardenSMProject creates a new Bitwarden Secret Manager project and a test secret
// Required environment variables:
//   - BITWARDEN_SM_ACCESS_TOKEN: Access token for authentication
//   - SSTART_E2E_BITWARDEN_ORGANIZATION_ID: Organization ID in Bitwarden
//   - BITWARDEN_SERVER_URL: (optional) Bitwarden server URL, defaults to https://vault.bitwarden.com
//
// Returns a BitwardenSMTestSetup with the project ID and a cleanup function
func SetupBitwardenSMProject(ctx context.Context, t *testing.T, projectName string, secretKey string, secretValue string) *BitwardenSMTestSetup {
	t.Helper()

	// Get required environment variables
	organizationID := os.Getenv("SSTART_E2E_BITWARDEN_ORGANIZATION_ID")
	accessToken := os.Getenv("BITWARDEN_SM_ACCESS_TOKEN")
	serverURL := os.Getenv("BITWARDEN_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://vault.bitwarden.com"
	}

	// Fail test if required environment variables are not set
	if organizationID == "" || accessToken == "" {
		t.Fatalf("Required environment variables not set: SSTART_E2E_BITWARDEN_ORGANIZATION_ID and BITWARDEN_SM_ACCESS_TOKEN are required")
	}

	// Ensure server URL doesn't end with /
	serverURL = strings.TrimSuffix(serverURL, "/")

	// Determine API and Identity URLs
	var apiURL, identityURL string
	if serverURL == "https://vault.bitwarden.com" || serverURL == "https://vault.bitwarden.com/" {
		apiURL = "https://api.bitwarden.com"
		identityURL = "https://identity.bitwarden.com"
	} else {
		// Self-hosted or custom server
		apiURL = serverURL + "/api"
		identityURL = serverURL + "/identity"
	}

	// Create SDK client
	client, err := sdk.NewBitwardenClient(&apiURL, &identityURL)
	if err != nil {
		t.Fatalf("Failed to create Bitwarden client: %v", err)
	}

	// Login with access token
	stateFile := (*string)(nil)
	if err := client.AccessTokenLogin(accessToken, stateFile); err != nil {
		client.Close()
		t.Fatalf("Failed to authenticate with Bitwarden: %v", err)
	}

	// Create project
	projectNameWithTimestamp := fmt.Sprintf("%s-%d", projectName, time.Now().Unix())
	projectResponse, err := client.Projects().Create(organizationID, projectNameWithTimestamp)
	if err != nil {
		client.Close()
		t.Fatalf("Failed to create Bitwarden project: %v", err)
	}

	if projectResponse == nil {
		client.Close()
		t.Fatalf("Project creation response was empty")
	}

	projectID := projectResponse.ID
	if projectID == "" {
		client.Close()
		t.Fatalf("Project creation did not return a valid project ID")
	}

	// Create secret in the project
	secretResponse, err := client.Secrets().Create(secretKey, secretValue, "", organizationID, []string{projectID})
	if err != nil {
		// Clean up project on secret creation failure
		client.Projects().Delete([]string{projectID})
		client.Close()
		t.Fatalf("Failed to create Bitwarden secret: %v", err)
	}

	if secretResponse == nil {
		// Clean up project on secret creation failure
		client.Projects().Delete([]string{projectID})
		client.Close()
		t.Fatalf("Secret creation response was empty")
	}

	secretID := secretResponse.ID

	// Return setup with cleanup function
	return &BitwardenSMTestSetup{
		OrganizationID: organizationID,
		ProjectID:      projectID,
		Client:         client,
		Cleanup: func() error {
			// Delete the secret first
			if secretID != "" {
				client.Secrets().Delete([]string{secretID})
			}
			// Delete the project
			client.Projects().Delete([]string{projectID})
			// Close the client
			client.Close()
			return nil
		},
	}
}
