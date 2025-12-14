package onepassword

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/1password/onepassword-sdk-go"
	"github.com/dirathea/sstart/internal/provider"
)

// OnePasswordConfig represents the configuration for 1Password provider
type OnePasswordConfig struct {
	// Ref is the 1Password secret reference in the format: op://<vault>/<item>/[section/]<field>
	// Examples:
	//   - op://VaultName/ItemName/fieldName (specific field)
	//   - op://VaultName/ItemName/sectionName/fieldName (field in section)
	//   - op://VaultName/ItemName/sectionName (whole section)
	//   - op://VaultName/ItemName (whole item)
	Ref string `json:"ref" yaml:"ref"`
	// UseSectionPrefix controls whether section names are used as prefixes for field keys.
	// When true (default), fields in sections will have keys like "SectionName_FieldName".
	// When false, fields will use just "FieldName", and collisions will be warned.
	UseSectionPrefix *bool `json:"use_section_prefix,omitempty" yaml:"use_section_prefix,omitempty"`
}

// OnePasswordProvider implements the provider interface for 1Password
type OnePasswordProvider struct {
	client *onepassword.Client
}

func init() {
	provider.Register("1password", func() provider.Provider {
		return &OnePasswordProvider{}
	})
}

// Name returns the provider name
func (p *OnePasswordProvider) Name() string {
	return "1password"
}

// Fetch fetches secrets from 1Password
func (p *OnePasswordProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid 1password configuration: %w", err)
	}

	// Validate required fields
	if cfg.Ref == "" {
		return nil, fmt.Errorf("1password provider requires 'ref' field in configuration")
	}

	// Validate ref format
	if !strings.HasPrefix(cfg.Ref, "op://") {
		return nil, fmt.Errorf("1password ref must start with 'op://' (got: %s)", cfg.Ref)
	}

	// Ensure client is initialized
	if err := p.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize 1Password client: %w", err)
	}

	// Parse the ref to determine what we're fetching
	parsedRef, err := parseRef(cfg.Ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ref '%s': %w", cfg.Ref, err)
	}

	// Fetch the item once using vault and item from the ref
	// This is the key optimization: we only make one API call per unique vault/item combination
	item, err := p.getItem(ctx, parsedRef.Vault, parsedRef.Item)
	if err != nil {
		return nil, fmt.Errorf("failed to get item '%s/%s': %w", parsedRef.Vault, parsedRef.Item, err)
	}

	// Resolve ambiguous references (field vs section) using the already-fetched item
	if err := p.resolveAmbiguousRef(item, cfg, parsedRef); err != nil {
		return nil, err
	}

	// Extract secrets from the item based on the ref type
	var secretData map[string]interface{}

	if parsedRef.Field != "" {
		// Fetching a specific field (or field in section)
		secretData, err = p.extractField(item, cfg, parsedRef)
	} else if parsedRef.Section != "" {
		// Fetching a whole section
		secretData, err = p.extractSection(item, cfg, parsedRef)
	} else {
		// Fetching the whole item
		secretData, err = p.extractWholeItem(item, cfg, parsedRef)
	}
	if err != nil {
		return nil, err
	}

	kvs := make([]provider.KeyValue, 0)
	for k, v := range secretData {
		value := fmt.Sprintf("%v", v)
		kvs = append(kvs, provider.KeyValue{
			Key:   k,
			Value: value,
		})
	}

	return kvs, nil
}

// resolveAmbiguousRef resolves ambiguous references where part3 could be a field or section
// Uses the already-fetched item to avoid additional API calls
func (p *OnePasswordProvider) resolveAmbiguousRef(item *onepassword.Item, cfg *OnePasswordConfig, parsedRef *parsedRef) error {
	// If we have 3 parts (vault/item/part3), we need to determine if part3 is a section or field
	// Priority: top-level field takes precedence over section with the same name
	if parsedRef.Section == "" && parsedRef.Field != "" {
		// First, check if there's a top-level field with this name
		hasTopLevelField := false
		for _, field := range item.Fields {
			if field.SectionID == nil && field.Title == parsedRef.Field {
				hasTopLevelField = true
				break
			}
		}

		// Check if there's also a section with this name
		hasSection := false
		for _, section := range item.Sections {
			if section.Title == parsedRef.Field {
				hasSection = true
				break
			}
		}

		// If both exist, prioritize top-level field and warn
		if hasTopLevelField && hasSection {
			log.Printf("WARNING: Ambiguous reference '%s': both a top-level field '%s' and a section '%s' exist in item '%s/%s'. Using top-level field. To load the section instead, either: (1) rename the top-level field or section in 1Password to avoid ambiguity, or (2) use 'op://%s/%s' with use_section_prefix: true to load all fields from the item", cfg.Ref, parsedRef.Field, parsedRef.Field, parsedRef.Vault, parsedRef.Item, parsedRef.Vault, parsedRef.Item)
			// Keep as field reference (top-level field takes precedence)
		} else if hasSection && !hasTopLevelField {
			// Only section exists, treat as section reference
			parsedRef.Section = parsedRef.Field
			parsedRef.Field = ""
		}
		// If only top-level field exists, keep as field reference (default behavior)
	}
	return nil
}

// extractField extracts a specific field from an already-fetched 1Password item
func (p *OnePasswordProvider) extractField(item *onepassword.Item, cfg *OnePasswordConfig, parsedRef *parsedRef) (map[string]interface{}, error) {
	// Build a map of section IDs to section titles for lookup
	sectionIDToTitle := make(map[string]string)
	for _, section := range item.Sections {
		sectionIDToTitle[section.ID] = section.Title
	}

	// Find the field by title
	var fieldValue string
	var found bool

	if parsedRef.Section != "" {
		// Looking for a field in a specific section
		for _, field := range item.Fields {
			if field.Title == parsedRef.Field {
				if field.SectionID != nil {
					sectionTitle := sectionIDToTitle[*field.SectionID]
					if sectionTitle == parsedRef.Section {
						fieldValue = field.Value
						found = true
						break
					}
				}
			}
		}
	} else {
		// Looking for a top-level field - prioritize top-level fields
		// First pass: look for top-level fields only
		for _, field := range item.Fields {
			if field.Title == parsedRef.Field {
				// Check if this is a top-level field
				isTopLevel := false
				if field.SectionID == nil {
					isTopLevel = true
				} else if *field.SectionID == "" {
					isTopLevel = true
				} else if sectionIDToTitle[*field.SectionID] == "" {
					// Field is top-level if its section ID doesn't match any known section
					isTopLevel = true
				}

				if isTopLevel {
					fieldValue = field.Value
					found = true
					break
				}
			}
		}
		// If not found as top-level, this shouldn't happen after resolveAmbiguousRef,
		// but we'll search all fields as fallback
		if !found {
			for _, field := range item.Fields {
				if field.Title == parsedRef.Field {
					fieldValue = field.Value
					found = true
					break
				}
			}
		}
	}

	if !found {
		if parsedRef.Section != "" {
			return nil, fmt.Errorf("field '%s' not found in section '%s' of item '%s/%s'", parsedRef.Field, parsedRef.Section, parsedRef.Vault, parsedRef.Item)
		}
		return nil, fmt.Errorf("field '%s' not found in item '%s/%s'", parsedRef.Field, parsedRef.Vault, parsedRef.Item)
	}

	// Determine field key
	// Default: no prefix (just field name)
	// Only use prefix if explicitly enabled via use_section_prefix: true
	fieldName := parsedRef.Field
	if parsedRef.Section != "" && cfg.UseSectionPrefix != nil && *cfg.UseSectionPrefix {
		// Explicitly enabled: use prefix
		fieldName = fmt.Sprintf("%s_%s", parsedRef.Section, parsedRef.Field)
	}

	return map[string]interface{}{
		fieldName: fieldValue,
	}, nil
}

// extractSection extracts all fields from a specific section in an already-fetched 1Password item
func (p *OnePasswordProvider) extractSection(item *onepassword.Item, cfg *OnePasswordConfig, parsedRef *parsedRef) (map[string]interface{}, error) {
	// Find the section by title
	var sectionID *string
	for _, section := range item.Sections {
		if section.Title == parsedRef.Section {
			sectionID = &section.ID
			break
		}
	}
	if sectionID == nil {
		return nil, fmt.Errorf("section '%s' not found in item '%s/%s'", parsedRef.Section, parsedRef.Vault, parsedRef.Item)
	}

	// Extract all fields from the specified section
	// Default: no prefix (just field names)
	// Only use prefix if explicitly enabled via use_section_prefix: true
	secretData := make(map[string]interface{})
	for _, field := range item.Fields {
		if field.SectionID != nil && *field.SectionID == *sectionID {
			fieldKey := field.Title
			if cfg.UseSectionPrefix != nil && *cfg.UseSectionPrefix {
				fieldKey = fmt.Sprintf("%s_%s", parsedRef.Section, field.Title)
			}
			secretData[fieldKey] = field.Value
		}
	}

	if len(secretData) == 0 {
		return nil, fmt.Errorf("no fields found in section '%s' of item '%s/%s'", parsedRef.Section, parsedRef.Vault, parsedRef.Item)
	}

	return secretData, nil
}

// extractWholeItem extracts all fields from an already-fetched 1Password item
func (p *OnePasswordProvider) extractWholeItem(item *onepassword.Item, cfg *OnePasswordConfig, parsedRef *parsedRef) (map[string]interface{}, error) {
	// Build a map of section IDs to section titles
	sectionIDToTitle := make(map[string]string)
	for _, section := range item.Sections {
		sectionIDToTitle[section.ID] = section.Title
	}

	// Extract all fields from the item
	// Default: no prefix (just field names)
	// Only use prefix if explicitly enabled via use_section_prefix: true
	// When not using prefixes, prioritize top-level fields and warn about collisions
	secretData := make(map[string]interface{})
	keyToSection := make(map[string]string) // key -> section name (for collision detection when not using prefixes)
	processedKeys := make(map[string]bool)  // Track which keys we've already processed

	// First pass: Process top-level fields (they take precedence)
	p.processTopLevelFields(item, sectionIDToTitle, secretData, keyToSection, processedKeys)

	// Second pass: Process section fields
	if err := p.processSectionFields(item, cfg, parsedRef, sectionIDToTitle, secretData, keyToSection, processedKeys); err != nil {
		return nil, err
	}

	if len(secretData) == 0 {
		return nil, fmt.Errorf("no fields found in item '%s/%s'", parsedRef.Vault, parsedRef.Item)
	}

	return secretData, nil
}

// processTopLevelFields processes top-level fields from an item
// A field is considered top-level if:
// 1. SectionID is nil, OR
// 2. SectionID points to an empty string, OR
// 3. SectionID doesn't match any known section
func (p *OnePasswordProvider) processTopLevelFields(
	item *onepassword.Item,
	sectionIDToTitle map[string]string,
	secretData map[string]interface{},
	keyToSection map[string]string,
	processedKeys map[string]bool,
) {
	for _, field := range item.Fields {
		var isTopLevel bool
		if field.SectionID == nil {
			isTopLevel = true
		} else if *field.SectionID == "" {
			isTopLevel = true
		} else if sectionIDToTitle[*field.SectionID] == "" {
			isTopLevel = true
		}

		if isTopLevel {
			fieldKey := field.Title
			processedKeys[fieldKey] = true
			keyToSection[fieldKey] = "" // Empty string indicates top-level
			secretData[fieldKey] = field.Value
		}
	}
}

// processSectionFields processes fields from sections, checking for collisions
func (p *OnePasswordProvider) processSectionFields(
	item *onepassword.Item,
	cfg *OnePasswordConfig,
	parsedRef *parsedRef,
	sectionIDToTitle map[string]string,
	secretData map[string]interface{},
	keyToSection map[string]string,
	processedKeys map[string]bool,
) error {
	for _, field := range item.Fields {
		if field.SectionID == nil || *field.SectionID == "" {
			continue // Skip top-level fields (already processed)
		}

		// Field in a section - look up section title
		sectionTitle := sectionIDToTitle[*field.SectionID]

		// Skip fields that don't belong to a known section (already processed as top-level)
		if sectionTitle == "" {
			continue
		}

		fieldKey := field.Title
		if cfg.UseSectionPrefix != nil && *cfg.UseSectionPrefix {
			// Use prefix if explicitly enabled
			fieldKey = fmt.Sprintf("%s_%s", sectionTitle, field.Title)
			// With prefix, no collision possible
			secretData[fieldKey] = field.Value
		} else {
			// No prefix - check for collisions
			if processedKeys[fieldKey] {
				// Collision detected
				existingSection := keyToSection[fieldKey]
				if existingSection == "" {
					// Top-level field already exists - it takes precedence, warn about section field
					log.Printf("WARNING: Field '%s' exists as both top-level field and in section '%s' in item '%s/%s'. Top-level field will be used. To load the section field instead, either: (1) rename the top-level field or section in 1Password, or (2) use use_section_prefix: true to load both (section field will be '%s_%s')", fieldKey, sectionTitle, parsedRef.Vault, parsedRef.Item, sectionTitle, field.Title)
					// Skip this section field - top-level field already in secretData
				} else if existingSection != sectionTitle {
					// Field exists in multiple sections - this is an error
					return fmt.Errorf("collision detected: field '%s' exists in both section '%s' and section '%s' in item '%s/%s'. Use use_section_prefix: true to avoid collisions", fieldKey, existingSection, sectionTitle, parsedRef.Vault, parsedRef.Item)
				}
			} else {
				// No collision, add the field
				processedKeys[fieldKey] = true
				keyToSection[fieldKey] = sectionTitle
				secretData[fieldKey] = field.Value
			}
		}
	}
	return nil
}

// parsedRef represents a parsed 1Password reference
type parsedRef struct {
	Vault   string
	Item    string
	Section string
	Field   string
}

// parseRef parses a 1Password reference in the format: op://<vault>/<item>/[section/]<field>
func parseRef(ref string) (*parsedRef, error) {
	// Remove op:// prefix
	if !strings.HasPrefix(ref, "op://") {
		return nil, fmt.Errorf("ref must start with 'op://'")
	}
	path := strings.TrimPrefix(ref, "op://")

	// Split by /
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("ref must have at least vault and item (got: %s)", ref)
	}

	parsed := &parsedRef{
		Vault: parts[0],
		Item:  parts[1],
	}

	// Handle optional section and field
	if len(parts) == 3 {
		// Could be: op://vault/item/field OR op://vault/item/section
		// We need to check if this is a section or field by trying to resolve
		// For now, we'll assume it's a field if there's no 4th part
		parsed.Field = parts[2]
	} else if len(parts) == 4 {
		// op://vault/item/section/field
		parsed.Section = parts[2]
		parsed.Field = parts[3]
	} else if len(parts) > 4 {
		return nil, fmt.Errorf("ref has too many parts (got: %s)", ref)
	}

	return parsed, nil
}

// getItem retrieves an item from 1Password by vault name and item title
func (p *OnePasswordProvider) getItem(ctx context.Context, vaultName, itemTitle string) (*onepassword.Item, error) {
	// First, resolve vault name to vault ID
	vaultID, err := p.getVaultIDByName(ctx, vaultName)
	if err != nil {
		return nil, fmt.Errorf("failed to find vault '%s': %w", vaultName, err)
	}

	// Then, resolve item title to item ID
	itemID, err := p.getItemIDByTitle(ctx, vaultID, itemTitle)
	if err != nil {
		return nil, fmt.Errorf("failed to find item '%s' in vault '%s': %w", itemTitle, vaultName, err)
	}

	// Get the item using ItemsAPI
	item, err := p.client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item '%s' from vault '%s': %w", itemTitle, vaultName, err)
	}

	return &item, nil
}

// getVaultIDByName resolves a vault name to vault ID
func (p *OnePasswordProvider) getVaultIDByName(ctx context.Context, vaultName string) (string, error) {
	vaults, err := p.client.Vaults().List(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list vaults: %w", err)
	}

	for _, vault := range vaults {
		if vault.Title == vaultName {
			return vault.ID, nil
		}
	}

	return "", fmt.Errorf("vault '%s' not found", vaultName)
}

// getItemIDByTitle resolves an item title to item ID within a vault
func (p *OnePasswordProvider) getItemIDByTitle(ctx context.Context, vaultID, itemTitle string) (string, error) {
	items, err := p.client.Items().List(ctx, vaultID)
	if err != nil {
		return "", fmt.Errorf("failed to list items in vault: %w", err)
	}

	for _, item := range items {
		if item.Title == itemTitle {
			return item.ID, nil
		}
	}

	return "", fmt.Errorf("item '%s' not found in vault", itemTitle)
}

// ensureClient initializes the 1Password client if not already initialized
func (p *OnePasswordProvider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	// Get service account token from environment
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		return fmt.Errorf("OP_SERVICE_ACCOUNT_TOKEN environment variable is required")
	}

	// Create client with service account token
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("sstart", "1.0.0"),
	)
	if err != nil {
		return fmt.Errorf("failed to create 1Password client: %w", err)
	}

	p.client = client
	return nil
}

// parseConfig converts a map[string]interface{} to OnePasswordConfig
func parseConfig(config map[string]interface{}) (*OnePasswordConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg OnePasswordConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// No default value - section prefix is disabled by default
	// User must explicitly set use_section_prefix: true to enable it

	return &cfg, nil
}
