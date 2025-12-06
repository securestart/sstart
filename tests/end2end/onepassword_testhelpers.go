package end2end

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/1password/onepassword-sdk-go"
)

// SetupOnePasswordClient creates and returns a 1Password client for testing
// Requires OP_SERVICE_ACCOUNT_TOKEN environment variable
func SetupOnePasswordClient(ctx context.Context, t *testing.T) *onepassword.Client {
	t.Helper()

	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Fatalf("OP_SERVICE_ACCOUNT_TOKEN environment variable is required for 1Password tests")
	}

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("sstart-test", "1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create 1Password client: %v", err)
	}

	return client
}

// SetupOnePasswordVault ensures a test vault exists or creates one
// Returns the vault ID
func SetupOnePasswordVault(ctx context.Context, t *testing.T, client *onepassword.Client, vaultName string) string {
	t.Helper()

	// List all vaults to find the vault by name
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		t.Fatalf("Failed to list vaults: %v", err)
	}

	for _, vault := range vaults {
		if vault.Title == vaultName {
			return vault.ID
		}
	}

	// Vault not found - user needs to create it manually
	t.Fatalf("Vault '%s' not found. Please create it in 1Password before running tests.", vaultName)
	return ""
}

// generateUniqueID generates a unique ID for fields and sections
func generateUniqueID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// SetupOnePasswordItem creates a test item in 1Password with the specified configuration
// Returns the item ID
func SetupOnePasswordItem(ctx context.Context, t *testing.T, client *onepassword.Client, vaultID string, itemTitle string, fields map[string]string, sections map[string]map[string]string) string {
	t.Helper()

	// Build item fields
	itemFields := make([]onepassword.ItemField, 0)

	// Add top-level fields (not in sections)
	for fieldTitle, fieldValue := range fields {
		itemFields = append(itemFields, onepassword.ItemField{
			ID:       generateUniqueID(),
			Title:    fieldTitle,
			Value:    fieldValue,
			FieldType: onepassword.ItemFieldTypeText,
		})
	}

	// Build sections and their fields
	itemSections := make([]onepassword.ItemSection, 0)

	for sectionTitle, sectionFields := range sections {
		// Create section with unique ID
		sectionID := generateUniqueID()
		itemSections = append(itemSections, onepassword.ItemSection{
			ID:    sectionID,
			Title: sectionTitle,
		})

		// Add fields in this section
		for fieldTitle, fieldValue := range sectionFields {
			sectionIDPtr := &sectionID
			itemFields = append(itemFields, onepassword.ItemField{
				ID:        generateUniqueID(),
				Title:     fieldTitle,
				Value:     fieldValue,
				FieldType: onepassword.ItemFieldTypeText,
				SectionID: sectionIDPtr,
			})
		}
	}

	// Create item
	itemParams := onepassword.ItemCreateParams{
		VaultID:  vaultID,
		Title:    itemTitle,
		Category: onepassword.ItemCategorySecureNote,
		Fields:   itemFields,
		Sections: itemSections,
	}

	item, err := client.Items().Create(ctx, itemParams)
	if err != nil {
		t.Fatalf("Failed to create 1Password item: %v", err)
	}

	return item.ID
}

// CleanupOnePasswordItem deletes a test item from 1Password
func CleanupOnePasswordItem(ctx context.Context, t *testing.T, client *onepassword.Client, vaultID, itemID string) {
	t.Helper()

	err := client.Items().Delete(ctx, vaultID, itemID)
	if err != nil {
		// Log error but don't fail test - cleanup is best effort
		t.Logf("Warning: Failed to cleanup 1Password item %s: %v", itemID, err)
	}
}

// GetOnePasswordItemByTitle finds an item by title in a vault
func GetOnePasswordItemByTitle(ctx context.Context, t *testing.T, client *onepassword.Client, vaultID, itemTitle string) *onepassword.Item {
	t.Helper()

	items, err := client.Items().List(ctx, vaultID)
	if err != nil {
		t.Fatalf("Failed to list items in vault: %v", err)
	}

	for _, itemOverview := range items {
		if itemOverview.Title == itemTitle {
			item, err := client.Items().Get(ctx, vaultID, itemOverview.ID)
			if err != nil {
				t.Fatalf("Failed to get item: %v", err)
			}
			return &item
		}
	}

	t.Fatalf("Item '%s' not found in vault", itemTitle)
	return nil
}

