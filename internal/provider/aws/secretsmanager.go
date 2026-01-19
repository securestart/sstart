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
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	// RoleArn is the ARN of the IAM role to assume using SSO JWT (optional)
	// When set with SSO tokens, triggers AssumeRoleWithWebIdentity authentication
	RoleArn string `json:"role_arn,omitempty" yaml:"role_arn,omitempty"`
	// SessionName is the name for the assumed role session (optional, defaults to "sstart-session")
	SessionName string `json:"session_name,omitempty" yaml:"session_name,omitempty"`
	// Duration is the session duration in seconds (optional, defaults to 3600)
	Duration int32 `json:"duration,omitempty" yaml:"duration,omitempty"`

	// Internal: SSO tokens injected by the collector
	SSOAccessToken string `json:"-" yaml:"-"`
	SSOIDToken     string `json:"-" yaml:"-"`
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
func (p *SecretsManagerProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	ctx := secretContext.Ctx
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

	if err := p.ensureClient(ctx, cfg); err != nil {
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
		targetKey := k

		// Check if there's a specific mapping
		if mappedKey, exists := keys[k]; exists {
			if mappedKey == "==" {
				targetKey = k // Keep same name
			} else {
				targetKey = mappedKey
			}
		} else if len(keys) == 0 {
			// No keys specified means map everything
			targetKey = k
		} else {
			// Skip keys not in the mapping
			continue
		}

		value := fmt.Sprintf("%v", v)
		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: value,
		})
	}

	return kvs, nil
}

func (p *SecretsManagerProvider) ensureClient(ctx context.Context, cfg *SecretsManagerConfig) error {
	if p.client != nil {
		return nil
	}

	var awsCfg aws.Config
	var err error

	// Auto-detect: Use SSO JWT if tokens are present AND role_arn is configured
	if cfg.RoleArn != "" && (cfg.SSOIDToken != "" || cfg.SSOAccessToken != "") {
		awsCfg, err = p.assumeRoleWithJWT(ctx, cfg)
		if err != nil {
			return fmt.Errorf("failed to assume role with SSO JWT: %w", err)
		}
	} else {
		// Fall back to default AWS credential chain
		awsCfg, err = p.loadDefaultConfig(ctx, cfg)
		if err != nil {
			return err
		}
	}

	// Apply custom endpoint if provided (for LocalStack testing)
	opts := []func(*secretsmanager.Options){}
	if cfg.Endpoint != "" {
		opts = append(opts, func(o *secretsmanager.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	p.client = secretsmanager.NewFromConfig(awsCfg, opts...)
	return nil
}

// loadDefaultConfig loads AWS config using standard credential chain
func (p *SecretsManagerProvider) loadDefaultConfig(ctx context.Context, cfg *SecretsManagerConfig) (aws.Config, error) {
	// Build config options
	cfgOpts := []func(*config.LoadOptions) error{}

	// Use configured region if set
	if cfg.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(cfg.Region))
		p.region = cfg.Region
	}

	// When using a custom endpoint (e.g., LocalStack), use static credentials
	// to avoid trying to use EC2 IMDS or other credential sources that won't work
	if cfg.Endpoint != "" {
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", ""),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return aws.Config{}, err
	}

	// If no region was configured, use the one from AWS config or default
	if p.region == "" {
		p.region = awsCfg.Region
		if p.region == "" {
			p.region = "us-east-1"
		}
	}

	return awsCfg, nil
}

// assumeRoleWithJWT uses SSO JWT tokens to assume an AWS IAM role via STS AssumeRoleWithWebIdentity
func (p *SecretsManagerProvider) assumeRoleWithJWT(ctx context.Context, cfg *SecretsManagerConfig) (aws.Config, error) {
	// Prefer ID token, fall back to access token
	jwtToken := cfg.SSOIDToken
	if jwtToken == "" {
		jwtToken = cfg.SSOAccessToken
	}

	// Set defaults
	sessionName := cfg.SessionName
	if sessionName == "" {
		sessionName = "sstart-session"
	}
	duration := cfg.Duration
	if duration == 0 {
		duration = 3600
	}

	// Set region
	region := cfg.Region
	if region != "" {
		p.region = region
	} else {
		region = "us-east-1"
		p.region = region
	}

	// Load minimal config for STS client
	cfgOpts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}

	// For LocalStack, use static credentials for the initial STS call
	if cfg.Endpoint != "" {
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", ""),
		))
	}

	baseCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create STS client with custom endpoint if provided (for LocalStack)
	stsOpts := []func(*sts.Options){}
	if cfg.Endpoint != "" {
		stsOpts = append(stsOpts, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}
	stsClient := sts.NewFromConfig(baseCfg, stsOpts...)

	// Assume role using JWT token
	result, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(cfg.RoleArn),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(jwtToken),
		DurationSeconds:  aws.Int32(duration),
	})
	if err != nil {
		return aws.Config{}, fmt.Errorf("STS AssumeRoleWithWebIdentity failed: %w", err)
	}

	// Create credentials from STS response
	creds := credentials.NewStaticCredentialsProvider(
		*result.Credentials.AccessKeyId,
		*result.Credentials.SecretAccessKey,
		*result.Credentials.SessionToken,
	)

	return aws.Config{
		Region:      region,
		Credentials: creds,
	}, nil
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

	// Extract SSO tokens from the config map (injected by the collector)
	if accessToken, ok := config["_sso_access_token"].(string); ok {
		cfg.SSOAccessToken = accessToken
	}
	if idToken, ok := config["_sso_id_token"].(string); ok {
		cfg.SSOIDToken = idToken
	}

	return &cfg, nil
}
