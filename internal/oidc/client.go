package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/dirathea/sstart/internal/config"
	"github.com/google/uuid"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	// DefaultPort is the default port for the callback server
	DefaultPort = 5747
	// DefaultCallbackPath is the default path for the OIDC callback
	DefaultCallbackPath = "/auth/sstart"
	// DefaultTimeout is the default timeout for the authentication flow
	DefaultTimeout = 5 * time.Minute
)

// Client represents an OIDC client for SSO authentication
type Client struct {
	config    *config.OIDCConfig
	provider  rp.RelyingParty
	logger    *slog.Logger
	tokenPath string
}

// Tokens represents the OIDC tokens received after authentication
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// UserInfo represents the user information from the OIDC provider
type UserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
}

// AuthResult holds the result of a successful authentication
type AuthResult struct {
	Tokens   *Tokens
	UserInfo *UserInfo
}

// SSOSecretEnvVar is the environment variable name for the OIDC client secret
const SSOSecretEnvVar = "SSTART_SSO_SECRET"

// NewClient creates a new OIDC client from the provided configuration
func NewClient(cfg *config.OIDCConfig) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("OIDC configuration is required")
	}

	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	if len(cfg.Scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}

	// Check for client secret from environment variable
	// Environment variable takes precedence over config file
	if secret := os.Getenv(SSOSecretEnvVar); secret != "" {
		cfg.ClientSecret = secret
	}

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: false,
			Level:     slog.LevelInfo,
		}),
	)

	client := &Client{
		config:    cfg,
		logger:    logger,
		tokenPath: getDefaultTokenPath(),
	}

	return client, nil
}

// Login initiates the OIDC login flow
// It starts a local HTTP server to handle the callback, opens the browser for authentication,
// and returns the tokens upon successful authentication
func (c *Client) Login(ctx context.Context) (*AuthResult, error) {
	port := DefaultPort
	callbackPath := DefaultCallbackPath

	// Parse redirect URI if provided
	if c.config.RedirectURI != "" {
		// Extract port from redirect URI if possible
		// For now, we use the default port
	}

	redirectURI := fmt.Sprintf("http://localhost:%d%s", port, callbackPath)

	// Create cookie handler for secure state management
	key := []byte(uuid.New().String()[:16]) // Generate random key for this session
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: time.Minute,
	}

	// Enable HTTP logging in debug mode
	logging.EnableHTTPClient(httpClient, logging.WithClientGroup("oidc-client"))

	// Build provider options
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(httpClient),
		rp.WithLogger(c.logger),
		rp.WithSigningAlgsFromDiscovery(),
	}

	// Enable PKCE if no client secret or explicitly requested
	usePKCE := c.config.ClientSecret == "" || (c.config.PKCE != nil && *c.config.PKCE)
	if usePKCE {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	// Create the relying party (OIDC client)
	provider, err := rp.NewRelyingPartyOIDC(ctx, c.config.Issuer, c.config.ClientID, c.config.ClientSecret, redirectURI, c.config.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	c.provider = provider

	// Channel to receive authentication result
	resultChan := make(chan *AuthResult, 1)
	errorChan := make(chan error, 1)

	// Create a new ServeMux for this authentication session
	mux := http.NewServeMux()

	// State generator
	state := func() string {
		return uuid.New().String()
	}

	// URL options for the auth request
	urlOptions := []rp.URLParamOpt{}
	if c.config.ResponseMode != "" {
		urlOptions = append(urlOptions, rp.WithResponseModeURLParam(oidc.ResponseMode(c.config.ResponseMode)))
	}

	// Register login handler
	mux.Handle("/login", rp.AuthURLHandler(state, provider, urlOptions...))

	// Callback handler that processes the authentication response
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		result := &AuthResult{
			Tokens: &Tokens{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
				IDToken:      tokens.IDToken,
				TokenType:    tokens.TokenType,
				Expiry:       tokens.Expiry,
			},
		}

		if info != nil {
			result.UserInfo = &UserInfo{
				Subject:           info.Subject,
				Name:              info.Name,
				GivenName:         info.GivenName,
				FamilyName:        info.FamilyName,
				PreferredUsername: info.PreferredUsername,
				Email:             string(info.Email),
				EmailVerified:     bool(info.EmailVerified),
			}
		}

		resultChan <- result

		// Send success response to browser
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successHTML))
	}

	// Register callback handler
	mux.Handle(callbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider))

	// Create the HTTP server
	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	// Start the server in a goroutine
	go func() {
		c.logger.Info("starting authentication server", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- fmt.Errorf("failed to start callback server: %w", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Print login URL
	loginURL := fmt.Sprintf("http://localhost:%d/login", port)
	fmt.Printf("\n🔐 Opening browser for authentication...\n")
	fmt.Printf("   If the browser doesn't open, visit: %s\n\n", loginURL)

	// Try to open the browser
	if err := openBrowser(loginURL); err != nil {
		c.logger.Warn("failed to open browser", "error", err)
	}

	// Create a timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	// Wait for result or timeout
	var result *AuthResult
	select {
	case result = <-resultChan:
		c.logger.Info("authentication successful")
	case err := <-errorChan:
		_ = server.Shutdown(ctx)
		return nil, err
	case <-timeoutCtx.Done():
		_ = server.Shutdown(ctx)
		return nil, fmt.Errorf("authentication timed out after %v", DefaultTimeout)
	}

	// Shutdown the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Save tokens
	if err := c.SaveTokens(result.Tokens); err != nil {
		c.logger.Warn("failed to save tokens", "error", err)
	}

	return result, nil
}

// GetTokens loads and returns the stored tokens
func (c *Client) GetTokens() (*Tokens, error) {
	return c.LoadTokens()
}

// RefreshTokens refreshes the access token using the refresh token
func (c *Client) RefreshTokens(ctx context.Context) (*Tokens, error) {
	tokens, err := c.LoadTokens()
	if err != nil {
		return nil, fmt.Errorf("failed to load tokens: %w", err)
	}

	if tokens.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Initialize provider if not already done
	if c.provider == nil {
		redirectURI := fmt.Sprintf("http://localhost:%d%s", DefaultPort, DefaultCallbackPath)

		key := []byte(uuid.New().String()[:16])
		cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

		httpClient := &http.Client{Timeout: time.Minute}

		options := []rp.Option{
			rp.WithCookieHandler(cookieHandler),
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
			rp.WithHTTPClient(httpClient),
			rp.WithLogger(c.logger),
			rp.WithSigningAlgsFromDiscovery(),
		}

		provider, err := rp.NewRelyingPartyOIDC(ctx, c.config.Issuer, c.config.ClientID, c.config.ClientSecret, redirectURI, c.config.Scopes, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		c.provider = provider
	}

	// Refresh the tokens
	newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, c.provider, tokens.RefreshToken, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	result := &Tokens{
		AccessToken:  newTokens.AccessToken,
		RefreshToken: newTokens.RefreshToken,
		IDToken:      newTokens.IDToken,
		TokenType:    newTokens.TokenType,
		Expiry:       newTokens.Expiry,
	}

	// Save the new tokens
	if err := c.SaveTokens(result); err != nil {
		c.logger.Warn("failed to save refreshed tokens", "error", err)
	}

	return result, nil
}

// IsAuthenticated checks if valid tokens exist
func (c *Client) IsAuthenticated() bool {
	tokens, err := c.LoadTokens()
	if err != nil {
		return false
	}

	// Check if access token exists and is not expired
	if tokens.AccessToken == "" {
		return false
	}

	// If expiry is set and in the past, consider not authenticated
	if !tokens.Expiry.IsZero() && tokens.Expiry.Before(time.Now()) {
		// Could try to refresh, but for now just report as not authenticated
		return false
	}

	return true
}

// GetAccessToken returns the current access token, refreshing if needed
func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	tokens, err := c.LoadTokens()
	if err != nil {
		return "", fmt.Errorf("not authenticated: %w", err)
	}

	// Check if token is expired
	if !tokens.Expiry.IsZero() && tokens.Expiry.Before(time.Now()) {
		// Try to refresh
		if tokens.RefreshToken != "" {
			newTokens, err := c.RefreshTokens(ctx)
			if err != nil {
				return "", fmt.Errorf("token expired and refresh failed: %w", err)
			}
			return newTokens.AccessToken, nil
		}
		return "", fmt.Errorf("token expired and no refresh token available")
	}

	return tokens.AccessToken, nil
}

// successHTML is the HTML page shown after successful authentication
const successHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #e4e4e7;
        }
        .container {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 1rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        .icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #10b981, #059669);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
            animation: pulse 2s ease-in-out infinite;
        }
        .icon svg {
            width: 40px;
            height: 40px;
            stroke: white;
            stroke-width: 3;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        h1 {
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: #f4f4f5;
        }
        p {
            color: #a1a1aa;
            font-size: 1rem;
            line-height: 1.6;
        }
        .close-hint {
            margin-top: 2rem;
            font-size: 0.875rem;
            color: #71717a;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
            </svg>
        </div>
        <h1>Authentication Successful</h1>
        <p>You have been successfully authenticated.<br>You can close this window and return to your terminal.</p>
        <p class="close-hint">This window can be safely closed.</p>
    </div>
    <script>
        // Attempt to close the window after a delay
        setTimeout(() => {
            window.close();
        }, 3000);
    </script>
</body>
</html>
`
