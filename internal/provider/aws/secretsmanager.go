package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/dirathea/sstart/internal/provider"
)

// SecretsManagerConfig represents the configuration for AWS Secrets Manager provider
type SecretsManagerConfig struct {
	// SecretID is the ARN or name of the secret in AWS Secrets Manager (required)
	SecretID string `json:"secret_id" yaml:"secret_id"`
	// Region is the AWS region where the secret is stored (optional)
	Region string `json:"region,omitempty" yaml:"region,omitempty"`
	// Endpoint is a custom endpoint URL for AWS Secrets Manager (optional, for local testing)
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

// SecretsManagerProvider implements the provider interface for AWS Secrets Manager
type SecretsManagerProvider struct {
	client *secretsmanager.Client
	region string
}

func init() {
	provider.Register("aws_secretsmanager", func() provider.Provider {
		return &SecretsManagerProvider{}
	})
}

// Name returns the provider name
func (p *SecretsManagerProvider) Name() string {
	return "aws_secretsmanager"
}

// Fetch fetches secrets from AWS Secrets Manager
func (p *SecretsManagerProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid aws_secretsmanager configuration: %w", err)
	}

	// Validate required fields
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("aws_secretsmanager provider requires 'secret_id' field in configuration")
	}

	// Set region if provided
	if cfg.Region != "" {
		p.region = cfg.Region
	}

	if err := p.ensureClient(ctx, cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("failed to initialize AWS client: %w", err)
	}

	// Fetch the secret from Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretID),
	}

	result, err := p.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret from AWS Secrets Manager: %w", err)
	}

	// Parse the secret value (assuming JSON format)
	var secretData map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secretData); err != nil {
		// If not JSON, treat as a single value
		secretKey := strings.ToUpper(strings.ReplaceAll(mapID, "-", "_")) + "_SECRET"
		log.Printf("WARN: Secret from provider '%s' is not JSON format. Secret loaded to %s", mapID, secretKey)
		return []provider.KeyValue{
			{Key: secretKey, Value: *result.SecretString},
		}, nil
	}

	// Map keys according to configuration
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

func (p *SecretsManagerProvider) ensureClient(ctx context.Context, endpoint string) error {
	if p.client != nil {
		return nil
	}

	// Build config options
	cfgOpts := []func(*config.LoadOptions) error{}

	// Use configured region if set
	if p.region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(p.region))
	}

	// When using a custom endpoint (e.g., LocalStack), use static credentials
	// to avoid trying to use EC2 IMDS or other credential sources that won't work
	if endpoint != "" {
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", ""),
		))
	}

	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return err
	}

	// If no region was configured, use the one from AWS config or default
	if p.region == "" {
		p.region = cfg.Region
		if p.region == "" {
			p.region = "us-east-1"
		}
	}

	// Apply custom endpoint if provided
	opts := []func(*secretsmanager.Options){}
	if endpoint != "" {
		opts = append(opts, func(o *secretsmanager.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	p.client = secretsmanager.NewFromConfig(cfg, opts...)
	return nil
}

// parseConfig converts a map[string]interface{} to SecretsManagerConfig
func parseConfig(config map[string]interface{}) (*SecretsManagerConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg SecretsManagerConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
