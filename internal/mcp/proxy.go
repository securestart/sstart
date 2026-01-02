package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	// NamespaceSeparator is used to prefix primitive names with server ID
	NamespaceSeparator = "/"
)

// Proxy implements the MCP proxy that aggregates multiple downstream servers
type Proxy struct {
	manager   *ServerManager
	transport Transport
	ctx       context.Context
	cancel    context.CancelFunc

	// Proxy info
	proxyInfo Implementation

	// Client info (received during initialization)
	clientInfo         *Implementation
	clientCapabilities *ClientCapabilities

	// Aggregated primitives cache
	toolsCache             []Tool
	resourcesCache         []Resource
	resourceTemplatesCache []ResourceTemplate
	promptsCache           []Prompt
	cacheOnce              sync.Once
	cacheMu                sync.RWMutex
}

// NewProxy creates a new MCP proxy
func NewProxy(manager *ServerManager, transport Transport, version string) *Proxy {
	return &Proxy{
		manager:   manager,
		transport: transport,
		proxyInfo: Implementation{
			Name:    "sstart-mcp-proxy",
			Version: version,
		},
	}
}

// Run starts the proxy and processes messages until the context is cancelled or EOF
func (p *Proxy) Run(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	defer p.cancel()

	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		msg, err := p.transport.ReadMessage()
		if err != nil {
			if err == io.EOF {
				return nil // Client disconnected
			}
			return fmt.Errorf("failed to read message: %w", err)
		}

		resp, err := p.handleMessage(msg)
		if err != nil {
			// Log error but continue
			fmt.Fprintf(os.Stderr, "Error handling message: %v\n", err)
			if msg.ID != nil {
				errResp, _ := NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
				p.transport.WriteMessage(errResp)
			}
			continue
		}

		if resp != nil {
			if err := p.transport.WriteMessage(resp); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing response: %v\n", err)
			}
		}
	}
}

// Stop stops the proxy and all downstream servers
func (p *Proxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	return p.manager.StopAll()
}

// handleMessage routes and handles an incoming JSON-RPC message
func (p *Proxy) handleMessage(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	switch msg.Method {
	case MethodInitialize:
		return p.handleInitialize(msg)
	case MethodInitialized:
		// Notification, no response needed
		return nil, nil
	case MethodPing:
		return p.handlePing(msg)
	case MethodToolsList:
		return p.handleToolsList(msg)
	case MethodToolsCall:
		return p.handleToolsCall(msg)
	case MethodResourcesList:
		return p.handleResourcesList(msg)
	case MethodResourcesRead:
		return p.handleResourcesRead(msg)
	case MethodResourcesTemplatesList:
		return p.handleResourcesTemplatesList(msg)
	case MethodPromptsList:
		return p.handlePromptsList(msg)
	case MethodPromptsGet:
		return p.handlePromptsGet(msg)
	default:
		if msg.ID != nil {
			return NewJSONRPCErrorResponse(msg.ID.Value(), MethodNotFound, fmt.Sprintf("method not found: %s", msg.Method), nil)
		}
		return nil, nil
	}
}

// handleInitialize handles the initialize request
func (p *Proxy) handleInitialize(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	var params InitializeParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, "invalid initialize params", nil)
	}

	p.clientInfo = &params.ClientInfo
	p.clientCapabilities = &params.Capabilities

	// Start all downstream servers lazily or eagerly based on config
	// For now, we'll start them lazily when first accessed

	// Return our aggregated capabilities
	result := InitializeResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities: &ServerCapabilities{
			Tools:     &ToolCapabilities{ListChanged: false},
			Resources: &ResourceCapabilities{Subscribe: false, ListChanged: false},
			Prompts:   &PromptCapabilities{ListChanged: false},
		},
		ServerInfo:   &p.proxyInfo,
		Instructions: "sstart MCP proxy - aggregates multiple MCP servers with secret injection",
	}

	return NewJSONRPCResponse(msg.ID.Value(), result)
}

// handlePing handles the ping request
func (p *Proxy) handlePing(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	return NewJSONRPCResponse(msg.ID.Value(), struct{}{})
}

// handleToolsList aggregates tools from all downstream servers
func (p *Proxy) handleToolsList(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	tools, err := p.getAggregatedTools()
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	result := ToolsListResult{
		Tools: tools,
	}

	return NewJSONRPCResponse(msg.ID.Value(), result)
}

// handleToolsCall routes a tool call to the appropriate downstream server
func (p *Proxy) handleToolsCall(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	var params ToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, "invalid tool call params", nil)
	}

	// Parse server ID from tool name (format: serverID/toolName)
	serverID, toolName, err := p.parseNamespacedName(params.Name)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, err.Error(), nil)
	}

	// Get or start the server
	server, err := p.manager.GetOrStartServer(p.ctx, serverID)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Ensure server is initialized
	if err := p.ensureServerInitialized(server); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Create the forwarded request with the original tool name (without prefix)
	forwardParams := ToolCallParams{
		Name:      toolName,
		Arguments: params.Arguments,
	}

	forwardMsg, err := NewJSONRPCRequest(msg.ID.Value(), MethodToolsCall, forwardParams)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Forward to downstream server
	resp, err := server.ForwardRequest(p.ctx, forwardMsg)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	return resp, nil
}

// handleResourcesList aggregates resources from all downstream servers
func (p *Proxy) handleResourcesList(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	resources, err := p.getAggregatedResources()
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	result := ResourcesListResult{
		Resources: resources,
	}

	return NewJSONRPCResponse(msg.ID.Value(), result)
}

// handleResourcesRead routes a resource read to the appropriate downstream server
func (p *Proxy) handleResourcesRead(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	var params ResourcesReadParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, "invalid resource read params", nil)
	}

	// Parse server ID from URI (format: serverID/originalURI)
	serverID, originalURI, err := p.parseNamespacedName(params.URI)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, err.Error(), nil)
	}

	// Get or start the server
	server, err := p.manager.GetOrStartServer(p.ctx, serverID)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Ensure server is initialized
	if err := p.ensureServerInitialized(server); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Create the forwarded request with the original URI
	forwardParams := ResourcesReadParams{
		URI: originalURI,
	}

	forwardMsg, err := NewJSONRPCRequest(msg.ID.Value(), MethodResourcesRead, forwardParams)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Forward to downstream server
	resp, err := server.ForwardRequest(p.ctx, forwardMsg)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	return resp, nil
}

// handleResourcesTemplatesList aggregates resource templates from all downstream servers
func (p *Proxy) handleResourcesTemplatesList(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	templates, err := p.getAggregatedResourceTemplates()
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	result := ResourceTemplatesListResult{
		ResourceTemplates: templates,
	}

	return NewJSONRPCResponse(msg.ID.Value(), result)
}

// handlePromptsList aggregates prompts from all downstream servers
func (p *Proxy) handlePromptsList(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	prompts, err := p.getAggregatedPrompts()
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	result := PromptsListResult{
		Prompts: prompts,
	}

	return NewJSONRPCResponse(msg.ID.Value(), result)
}

// handlePromptsGet routes a prompt get to the appropriate downstream server
func (p *Proxy) handlePromptsGet(msg *JSONRPCMessage) (*JSONRPCMessage, error) {
	var params PromptsGetParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, "invalid prompt get params", nil)
	}

	// Parse server ID from prompt name (format: serverID/promptName)
	serverID, promptName, err := p.parseNamespacedName(params.Name)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InvalidParams, err.Error(), nil)
	}

	// Get or start the server
	server, err := p.manager.GetOrStartServer(p.ctx, serverID)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Ensure server is initialized
	if err := p.ensureServerInitialized(server); err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Create the forwarded request with the original prompt name
	forwardParams := PromptsGetParams{
		Name:      promptName,
		Arguments: params.Arguments,
	}

	forwardMsg, err := NewJSONRPCRequest(msg.ID.Value(), MethodPromptsGet, forwardParams)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	// Forward to downstream server
	resp, err := server.ForwardRequest(p.ctx, forwardMsg)
	if err != nil {
		return NewJSONRPCErrorResponse(msg.ID.Value(), InternalError, err.Error(), nil)
	}

	return resp, nil
}

// parseNamespacedName parses a namespaced name (serverID/name) into its components
func (p *Proxy) parseNamespacedName(namespacedName string) (serverID, name string, err error) {
	idx := strings.Index(namespacedName, NamespaceSeparator)
	if idx == -1 {
		return "", "", fmt.Errorf("invalid namespaced name '%s': missing server ID prefix", namespacedName)
	}

	serverID = namespacedName[:idx]
	name = namespacedName[idx+1:]

	if serverID == "" {
		return "", "", fmt.Errorf("invalid namespaced name '%s': empty server ID", namespacedName)
	}
	if name == "" {
		return "", "", fmt.Errorf("invalid namespaced name '%s': empty name", namespacedName)
	}

	return serverID, name, nil
}

// namespaceName prefixes a name with the server ID
func (p *Proxy) namespaceName(serverID, name string) string {
	return serverID + NamespaceSeparator + name
}

// ensureServerInitialized ensures the server is started and initialized
func (p *Proxy) ensureServerInitialized(server *Server) error {
	if server.Capabilities() != nil {
		return nil // Already initialized
	}

	clientInfo := Implementation{
		Name:    "sstart-mcp-proxy",
		Version: "0.1.0",
	}

	var clientCapabilities ClientCapabilities
	if p.clientCapabilities != nil {
		// Pass through relevant client capabilities
		clientCapabilities = *p.clientCapabilities
	}

	return server.Initialize(p.ctx, clientInfo, clientCapabilities)
}

// getAggregatedTools fetches and aggregates tools from all servers
func (p *Proxy) getAggregatedTools() ([]Tool, error) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	var allTools []Tool

	for _, serverID := range p.manager.Servers() {
		server, err := p.manager.GetOrStartServer(p.ctx, serverID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to start server '%s': %v\n", serverID, err)
			continue
		}

		if err := p.ensureServerInitialized(server); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize server '%s': %v\n", serverID, err)
			continue
		}

		tools, err := server.FetchTools(p.ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch tools from server '%s': %v\n", serverID, err)
			continue
		}

		// Namespace the tools
		for _, tool := range tools {
			namespacedTool := Tool{
				Name:        p.namespaceName(serverID, tool.Name),
				Description: tool.Description,
				InputSchema: tool.InputSchema,
			}
			allTools = append(allTools, namespacedTool)
		}
	}

	return allTools, nil
}

// getAggregatedResources fetches and aggregates resources from all servers
func (p *Proxy) getAggregatedResources() ([]Resource, error) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	var allResources []Resource

	for _, serverID := range p.manager.Servers() {
		server, err := p.manager.GetOrStartServer(p.ctx, serverID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to start server '%s': %v\n", serverID, err)
			continue
		}

		if err := p.ensureServerInitialized(server); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize server '%s': %v\n", serverID, err)
			continue
		}

		resources, err := server.FetchResources(p.ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch resources from server '%s': %v\n", serverID, err)
			continue
		}

		// Namespace the resources
		for _, resource := range resources {
			namespacedResource := Resource{
				URI:         p.namespaceName(serverID, resource.URI),
				Name:        p.namespaceName(serverID, resource.Name),
				Description: resource.Description,
				MIMEType:    resource.MIMEType,
			}
			allResources = append(allResources, namespacedResource)
		}
	}

	return allResources, nil
}

// getAggregatedResourceTemplates fetches and aggregates resource templates from all servers
func (p *Proxy) getAggregatedResourceTemplates() ([]ResourceTemplate, error) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	var allTemplates []ResourceTemplate

	for _, serverID := range p.manager.Servers() {
		server, err := p.manager.GetOrStartServer(p.ctx, serverID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to start server '%s': %v\n", serverID, err)
			continue
		}

		if err := p.ensureServerInitialized(server); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize server '%s': %v\n", serverID, err)
			continue
		}

		templates, err := server.FetchResourceTemplates(p.ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch resource templates from server '%s': %v\n", serverID, err)
			continue
		}

		// Namespace the templates
		for _, template := range templates {
			namespacedTemplate := ResourceTemplate{
				URITemplate: p.namespaceName(serverID, template.URITemplate),
				Name:        p.namespaceName(serverID, template.Name),
				Description: template.Description,
				MIMEType:    template.MIMEType,
			}
			allTemplates = append(allTemplates, namespacedTemplate)
		}
	}

	return allTemplates, nil
}

// getAggregatedPrompts fetches and aggregates prompts from all servers
func (p *Proxy) getAggregatedPrompts() ([]Prompt, error) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	var allPrompts []Prompt

	for _, serverID := range p.manager.Servers() {
		server, err := p.manager.GetOrStartServer(p.ctx, serverID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to start server '%s': %v\n", serverID, err)
			continue
		}

		if err := p.ensureServerInitialized(server); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize server '%s': %v\n", serverID, err)
			continue
		}

		prompts, err := server.FetchPrompts(p.ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch prompts from server '%s': %v\n", serverID, err)
			continue
		}

		// Namespace the prompts
		for _, prompt := range prompts {
			namespacedPrompt := Prompt{
				Name:        p.namespaceName(serverID, prompt.Name),
				Description: prompt.Description,
				Arguments:   prompt.Arguments,
			}
			allPrompts = append(allPrompts, namespacedPrompt)
		}
	}

	return allPrompts, nil
}
