// Package mcp implements the Model Context Protocol (MCP) proxy functionality.
// It provides types and utilities for JSON-RPC 2.0 communication and MCP message handling.
// This package uses types from the official MCP SDK where possible, with custom
// JSON-RPC transport layer for our proxy implementation.
package mcp

import (
	"encoding/json"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// JSONRPCVersion is the JSON-RPC protocol version
	JSONRPCVersion = "2.0"

	// MCPProtocolVersion is the MCP protocol version supported by this implementation
	MCPProtocolVersion = "2024-11-05"
)

// JSON-RPC 2.0 Error Codes
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// MCP Method names
const (
	MethodInitialize             = "initialize"
	MethodInitialized            = "notifications/initialized"
	MethodToolsList              = "tools/list"
	MethodToolsCall              = "tools/call"
	MethodResourcesList          = "resources/list"
	MethodResourcesRead          = "resources/read"
	MethodResourcesTemplatesList = "resources/templates/list"
	MethodPromptsList            = "prompts/list"
	MethodPromptsGet             = "prompts/get"
	MethodPing                   = "ping"
	MethodCancelled              = "notifications/cancelled"
	MethodProgress               = "notifications/progress"
)

// Re-export SDK types for use in our implementation
// Core MCP primitives
type (
	Tool             = sdk.Tool
	Resource         = sdk.Resource
	ResourceTemplate = sdk.ResourceTemplate
	Prompt           = sdk.Prompt
	PromptArgument   = sdk.PromptArgument
	Content          = sdk.Content
	PromptMessage    = sdk.PromptMessage
)

// Implementation and capabilities from SDK
type (
	Implementation       = sdk.Implementation
	ClientCapabilities   = sdk.ClientCapabilities
	ServerCapabilities   = sdk.ServerCapabilities
	ToolCapabilities     = sdk.ToolCapabilities
	ResourceCapabilities = sdk.ResourceCapabilities
	PromptCapabilities   = sdk.PromptCapabilities
)

// Request/Response types from SDK
type (
	InitializeResult            = sdk.InitializeResult
	CallToolParams              = sdk.CallToolParams
	CallToolResult              = sdk.CallToolResult
	ListToolsResult             = sdk.ListToolsResult
	ListResourcesResult         = sdk.ListResourcesResult
	ListResourceTemplatesResult = sdk.ListResourceTemplatesResult
	ListPromptsResult           = sdk.ListPromptsResult
	ReadResourceParams          = sdk.ReadResourceParams
	ReadResourceResult          = sdk.ReadResourceResult
	GetPromptParams             = sdk.GetPromptParams
	GetPromptResult             = sdk.GetPromptResult
)

// InitializeParams represents the parameters for the initialize request
// We define this ourselves for unmarshaling from our JSON-RPC layer
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// PaginatedRequest represents a request with pagination
type PaginatedRequest struct {
	Cursor *string `json:"cursor,omitempty"`
}

// RequestID represents a JSON-RPC request ID which can be string, number, or null
type RequestID struct {
	value interface{}
}

// NewRequestID creates a new RequestID from a value
func NewRequestID(v interface{}) RequestID {
	return RequestID{value: v}
}

// Value returns the underlying value of the RequestID
func (id RequestID) Value() interface{} {
	return id.value
}

// IsNull returns true if the RequestID is null/nil
func (id RequestID) IsNull() bool {
	return id.value == nil
}

// MarshalJSON implements json.Marshaler
func (id RequestID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.value)
}

// UnmarshalJSON implements json.Unmarshaler
func (id *RequestID) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &id.value)
}

// JSONRPCMessage represents a generic JSON-RPC 2.0 message (request, response, or notification)
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *RequestID      `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// IsRequest returns true if this is a JSON-RPC request (has method and id)
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && m.ID != nil && !m.ID.IsNull()
}

// IsNotification returns true if this is a JSON-RPC notification (has method, no id)
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && (m.ID == nil || m.ID.IsNull())
}

// IsResponse returns true if this is a JSON-RPC response (has result or error)
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Result != nil || m.Error != nil
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface
func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// NewJSONRPCRequest creates a new JSON-RPC request message
func NewJSONRPCRequest(id interface{}, method string, params interface{}) (*JSONRPCMessage, error) {
	var paramsRaw json.RawMessage
	if params != nil {
		var err error
		paramsRaw, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
	}

	reqID := NewRequestID(id)
	return &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Method:  method,
		Params:  paramsRaw,
	}, nil
}

// NewJSONRPCNotification creates a new JSON-RPC notification message (no id)
func NewJSONRPCNotification(method string, params interface{}) (*JSONRPCMessage, error) {
	var paramsRaw json.RawMessage
	if params != nil {
		var err error
		paramsRaw, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
	}

	return &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  paramsRaw,
	}, nil
}

// NewJSONRPCResponse creates a new JSON-RPC response message
func NewJSONRPCResponse(id interface{}, result interface{}) (*JSONRPCMessage, error) {
	var resultRaw json.RawMessage
	if result != nil {
		var err error
		resultRaw, err = json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}
	}

	reqID := NewRequestID(id)
	return &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Result:  resultRaw,
	}, nil
}

// NewJSONRPCErrorResponse creates a new JSON-RPC error response message
func NewJSONRPCErrorResponse(id interface{}, code int, message string, data interface{}) (*JSONRPCMessage, error) {
	var dataRaw json.RawMessage
	if data != nil {
		var err error
		dataRaw, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal error data: %w", err)
		}
	}

	reqID := NewRequestID(id)
	return &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    dataRaw,
		},
	}, nil
}

// ToolCallParams is our custom params type for tools/call
// Using our own to avoid SDK's complex generic request types
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ResourcesReadParams is our custom params type for resources/read
type ResourcesReadParams struct {
	URI string `json:"uri"`
}

// PromptsGetParams is our custom params type for prompts/get
type PromptsGetParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolsListResult is our result type for tools/list
type ToolsListResult struct {
	Tools      []Tool  `json:"tools"`
	NextCursor *string `json:"nextCursor,omitempty"`
}

// ResourcesListResult is our result type for resources/list
type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor *string    `json:"nextCursor,omitempty"`
}

// ResourceTemplatesListResult is our result type for resources/templates/list
type ResourceTemplatesListResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
	NextCursor        *string            `json:"nextCursor,omitempty"`
}

// PromptsListResult is our result type for prompts/list
type PromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor *string  `json:"nextCursor,omitempty"`
}
