package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

// ServerConfig represents the configuration for a downstream MCP server
type ServerConfig struct {
	ID      string   `yaml:"id"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
	// Future: Secrets []string `yaml:"secrets"` for selective injection
}

// ServerState represents the current state of a server
type ServerState int

const (
	ServerStateStopped ServerState = iota
	ServerStateStarting
	ServerStateRunning
	ServerStateStopping
	ServerStateError
)

// Server represents a downstream MCP server instance
type Server struct {
	config     ServerConfig
	cmd        *exec.Cmd
	transport  *PipeTransport
	state      atomic.Int32
	stateMu    sync.RWMutex
	startMu    sync.Mutex
	secrets    map[string]string
	inherit    bool
	cancelFunc context.CancelFunc

	// Cached capabilities after initialization
	capabilities *ServerCapabilities
	serverInfo   *Implementation

	// Cached primitives (populated lazily)
	tools             []Tool
	resources         []Resource
	resourceTemplates []ResourceTemplate
	prompts           []Prompt
	primitivesOnce    sync.Once
	primitivesErr     error

	// Request tracking for responses
	pendingRequests   map[interface{}]chan *JSONRPCMessage
	pendingRequestsMu sync.Mutex
	nextRequestID     atomic.Int64
}

// NewServer creates a new server instance with the given configuration
func NewServer(config ServerConfig, secrets map[string]string, inherit bool) *Server {
	return &Server{
		config:          config,
		secrets:         secrets,
		inherit:         inherit,
		pendingRequests: make(map[interface{}]chan *JSONRPCMessage),
	}
}

// ID returns the server's ID
func (s *Server) ID() string {
	return s.config.ID
}

// State returns the current server state
func (s *Server) State() ServerState {
	return ServerState(s.state.Load())
}

// IsRunning returns true if the server is running
func (s *Server) IsRunning() bool {
	return s.State() == ServerStateRunning
}

// buildEnv builds the environment variable slice for the subprocess
func (s *Server) buildEnv() []string {
	var env []string

	// Start with system environment if inheriting
	if s.inherit {
		env = os.Environ()
	}

	// Add collected secrets
	for key, value := range s.secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// Start starts the downstream MCP server subprocess
func (s *Server) Start(ctx context.Context) error {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if s.State() == ServerStateRunning {
		return nil // Already running
	}

	s.state.Store(int32(ServerStateStarting))

	// Create a cancellable context for this server
	serverCtx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	// Create the command
	s.cmd = exec.CommandContext(serverCtx, s.config.Command, s.config.Args...)
	s.cmd.Env = s.buildEnv()

	// Set up pipes for stdio communication
	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		s.state.Store(int32(ServerStateError))
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		s.state.Store(int32(ServerStateError))
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Connect stderr to our stderr for logging
	s.cmd.Stderr = os.Stderr

	// Create transport
	s.transport = NewPipeTransport(stdin, stdout)

	// Start the process
	if err := s.cmd.Start(); err != nil {
		s.transport.Close()
		s.state.Store(int32(ServerStateError))
		return fmt.Errorf("failed to start server process: %w", err)
	}

	s.state.Store(int32(ServerStateRunning))

	// Start goroutine to read responses
	go s.readResponses(serverCtx)

	// Start goroutine to wait for process exit
	go s.waitForExit()

	return nil
}

// readResponses reads messages from the server and routes responses to waiting requests
func (s *Server) readResponses(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := s.transport.ReadMessage()
		if err != nil {
			// Check if we're shutting down
			if s.State() != ServerStateRunning {
				return
			}
			// Log error but continue - might be temporary
			fmt.Fprintf(os.Stderr, "Error reading from server %s: %v\n", s.config.ID, err)
			return
		}

		// Route the message
		if msg.IsResponse() && msg.ID != nil {
			// Normalize the ID for lookup (JSON numbers unmarshal as float64)
			normalizedID := normalizeID(msg.ID.Value())
			s.pendingRequestsMu.Lock()
			if ch, ok := s.pendingRequests[normalizedID]; ok {
				ch <- msg
				delete(s.pendingRequests, normalizedID)
			}
			s.pendingRequestsMu.Unlock()
		}
		// Note: Server-initiated requests/notifications are not handled in this POC
		// They would need to be forwarded to the proxy for handling
	}
}

// normalizeID converts numeric IDs to int64 for consistent map key comparison
// This is needed because JSON numbers unmarshal as float64
func normalizeID(id interface{}) interface{} {
	switch v := id.(type) {
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	case int:
		return int64(v)
	case int32:
		return int64(v)
	default:
		return id
	}
}

// waitForExit waits for the server process to exit
func (s *Server) waitForExit() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Wait()
		s.state.Store(int32(ServerStateStopped))
	}
}

// Stop stops the downstream MCP server
func (s *Server) Stop() error {
	if s.State() != ServerStateRunning {
		return nil
	}

	s.state.Store(int32(ServerStateStopping))

	// Cancel the context
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	// Close transport
	if s.transport != nil {
		s.transport.Close()
	}

	// Wait for process to exit (with timeout handled by context)
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}

	s.state.Store(int32(ServerStateStopped))
	return nil
}

// SendRequest sends a JSON-RPC request to the server and waits for a response
func (s *Server) SendRequest(ctx context.Context, method string, params interface{}) (*JSONRPCMessage, error) {
	if s.State() != ServerStateRunning {
		return nil, fmt.Errorf("server %s is not running", s.config.ID)
	}

	// Generate request ID
	id := s.nextRequestID.Add(1)

	// Create request
	req, err := NewJSONRPCRequest(id, method, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Create response channel
	respCh := make(chan *JSONRPCMessage, 1)

	s.pendingRequestsMu.Lock()
	s.pendingRequests[id] = respCh
	s.pendingRequestsMu.Unlock()

	// Ensure we clean up if we exit early
	defer func() {
		s.pendingRequestsMu.Lock()
		delete(s.pendingRequests, id)
		s.pendingRequestsMu.Unlock()
	}()

	// Send request
	if err := s.transport.WriteMessage(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-respCh:
		return resp, nil
	}
}

// SendNotification sends a JSON-RPC notification to the server (no response expected)
func (s *Server) SendNotification(method string, params interface{}) error {
	if s.State() != ServerStateRunning {
		return fmt.Errorf("server %s is not running", s.config.ID)
	}

	notification, err := NewJSONRPCNotification(method, params)
	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return s.transport.WriteMessage(notification)
}

// ForwardRequest forwards a raw JSON-RPC message to the server and waits for a response
func (s *Server) ForwardRequest(ctx context.Context, msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	if s.State() != ServerStateRunning {
		return nil, fmt.Errorf("server %s is not running", s.config.ID)
	}

	if msg.ID == nil {
		// This is a notification, just forward it
		return nil, s.transport.WriteMessage(msg)
	}

	// Normalize the ID for consistent map key comparison
	normalizedID := normalizeID(msg.ID.Value())

	// Create response channel
	respCh := make(chan *JSONRPCMessage, 1)

	s.pendingRequestsMu.Lock()
	s.pendingRequests[normalizedID] = respCh
	s.pendingRequestsMu.Unlock()

	defer func() {
		s.pendingRequestsMu.Lock()
		delete(s.pendingRequests, normalizedID)
		s.pendingRequestsMu.Unlock()
	}()

	// Send the message
	if err := s.transport.WriteMessage(msg); err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-respCh:
		return resp, nil
	}
}

// Initialize sends the initialize request to the server
func (s *Server) Initialize(ctx context.Context, clientInfo Implementation, clientCapabilities ClientCapabilities) error {
	params := InitializeParams{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    clientCapabilities,
		ClientInfo:      clientInfo,
	}

	resp, err := s.SendRequest(ctx, MethodInitialize, params)
	if err != nil {
		return fmt.Errorf("failed to send initialize request: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("initialize failed: %s", resp.Error.Message)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to unmarshal initialize result: %w", err)
	}

	s.capabilities = result.Capabilities
	s.serverInfo = result.ServerInfo

	// Send initialized notification
	if err := s.SendNotification(MethodInitialized, nil); err != nil {
		return fmt.Errorf("failed to send initialized notification: %w", err)
	}

	return nil
}

// Capabilities returns the server's capabilities (available after initialization)
func (s *Server) Capabilities() *ServerCapabilities {
	return s.capabilities
}

// ServerInfo returns the server's info (available after initialization)
func (s *Server) ServerInfo() *Implementation {
	return s.serverInfo
}

// FetchTools fetches the list of tools from the server
func (s *Server) FetchTools(ctx context.Context) ([]Tool, error) {
	if s.capabilities == nil || s.capabilities.Tools == nil {
		return nil, nil // Server doesn't support tools
	}

	resp, err := s.SendRequest(ctx, MethodToolsList, &PaginatedRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tools: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", resp.Error.Message)
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tools list: %w", err)
	}

	// TODO: Handle pagination with NextCursor
	return result.Tools, nil
}

// FetchResources fetches the list of resources from the server
func (s *Server) FetchResources(ctx context.Context) ([]Resource, error) {
	if s.capabilities == nil || s.capabilities.Resources == nil {
		return nil, nil // Server doesn't support resources
	}

	resp, err := s.SendRequest(ctx, MethodResourcesList, &PaginatedRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resources: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("resources/list failed: %s", resp.Error.Message)
	}

	var result ResourcesListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resources list: %w", err)
	}

	// TODO: Handle pagination with NextCursor
	return result.Resources, nil
}

// FetchResourceTemplates fetches the list of resource templates from the server
func (s *Server) FetchResourceTemplates(ctx context.Context) ([]ResourceTemplate, error) {
	if s.capabilities == nil || s.capabilities.Resources == nil {
		return nil, nil // Server doesn't support resources
	}

	resp, err := s.SendRequest(ctx, MethodResourcesTemplatesList, &PaginatedRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource templates: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("resources/templates/list failed: %s", resp.Error.Message)
	}

	var result ResourceTemplatesListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource templates list: %w", err)
	}

	return result.ResourceTemplates, nil
}

// FetchPrompts fetches the list of prompts from the server
func (s *Server) FetchPrompts(ctx context.Context) ([]Prompt, error) {
	if s.capabilities == nil || s.capabilities.Prompts == nil {
		return nil, nil // Server doesn't support prompts
	}

	resp, err := s.SendRequest(ctx, MethodPromptsList, &PaginatedRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch prompts: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("prompts/list failed: %s", resp.Error.Message)
	}

	var result PromptsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal prompts list: %w", err)
	}

	// TODO: Handle pagination with NextCursor
	return result.Prompts, nil
}

// ServerManager manages multiple downstream MCP servers
type ServerManager struct {
	servers map[string]*Server
	secrets map[string]string
	inherit bool
	mu      sync.RWMutex
}

// NewServerManager creates a new server manager
func NewServerManager(configs []ServerConfig, secrets map[string]string, inherit bool) *ServerManager {
	servers := make(map[string]*Server)
	for _, cfg := range configs {
		servers[cfg.ID] = NewServer(cfg, secrets, inherit)
	}

	return &ServerManager{
		servers: servers,
		secrets: secrets,
		inherit: inherit,
	}
}

// GetServer returns a server by ID (does not start it)
func (m *ServerManager) GetServer(id string) (*Server, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	server, ok := m.servers[id]
	return server, ok
}

// GetOrStartServer returns a server, starting it if necessary (lazy initialization)
func (m *ServerManager) GetOrStartServer(ctx context.Context, id string) (*Server, error) {
	m.mu.RLock()
	server, ok := m.servers[id]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("server '%s' not found", id)
	}

	if server.IsRunning() {
		return server, nil
	}

	// Start the server
	if err := server.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start server '%s': %w", id, err)
	}

	return server, nil
}

// StartAll starts all configured servers
func (m *ServerManager) StartAll(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for id, server := range m.servers {
		if err := server.Start(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to start server '%s': %w", id, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors starting servers: %v", errs)
	}
	return nil
}

// StopAll stops all running servers
func (m *ServerManager) StopAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for id, server := range m.servers {
		if err := server.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop server '%s': %w", id, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping servers: %v", errs)
	}
	return nil
}

// Servers returns a list of all server IDs
func (m *ServerManager) Servers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.servers))
	for id := range m.servers {
		ids = append(ids, id)
	}
	return ids
}

// InitializeAll initializes all running servers
func (m *ServerManager) InitializeAll(ctx context.Context, clientInfo Implementation, clientCapabilities ClientCapabilities) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for id, server := range m.servers {
		if server.IsRunning() {
			if err := server.Initialize(ctx, clientInfo, clientCapabilities); err != nil {
				errs = append(errs, fmt.Errorf("failed to initialize server '%s': %w", id, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors initializing servers: %v", errs)
	}
	return nil
}
