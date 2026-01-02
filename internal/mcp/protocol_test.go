package mcp

import (
	"encoding/json"
	"testing"
)

func TestRequestID_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
	}{
		{"string id", "test-id-123"},
		{"integer id", 42},
		{"float id", 3.14},
		{"null id", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := NewRequestID(tt.value)

			// Marshal
			data, err := json.Marshal(id)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			// Unmarshal
			var parsed RequestID
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			// Compare - handle type differences (json numbers become float64)
			if tt.value == nil {
				if !parsed.IsNull() {
					t.Errorf("expected null, got %v", parsed.Value())
				}
			}
		})
	}
}

func TestRequestID_IsNull(t *testing.T) {
	nullID := NewRequestID(nil)
	if !nullID.IsNull() {
		t.Error("expected IsNull() to return true for nil value")
	}

	nonNullID := NewRequestID("test")
	if nonNullID.IsNull() {
		t.Error("expected IsNull() to return false for non-nil value")
	}
}

func TestJSONRPCMessage_IsRequest(t *testing.T) {
	reqID := NewRequestID(1)

	// Request (has method and id)
	request := &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Method:  "test/method",
	}
	if !request.IsRequest() {
		t.Error("expected IsRequest() to return true")
	}
	if request.IsNotification() {
		t.Error("expected IsNotification() to return false for request")
	}
	if request.IsResponse() {
		t.Error("expected IsResponse() to return false for request")
	}
}

func TestJSONRPCMessage_IsNotification(t *testing.T) {
	// Notification (has method, no id)
	notification := &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		Method:  "test/notification",
	}
	if !notification.IsNotification() {
		t.Error("expected IsNotification() to return true")
	}
	if notification.IsRequest() {
		t.Error("expected IsRequest() to return false for notification")
	}
	if notification.IsResponse() {
		t.Error("expected IsResponse() to return false for notification")
	}
}

func TestJSONRPCMessage_IsResponse(t *testing.T) {
	reqID := NewRequestID(1)

	// Success response
	successResponse := &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Result:  json.RawMessage(`{"success": true}`),
	}
	if !successResponse.IsResponse() {
		t.Error("expected IsResponse() to return true for success response")
	}

	// Error response
	errorResponse := &JSONRPCMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &reqID,
		Error: &JSONRPCError{
			Code:    InternalError,
			Message: "test error",
		},
	}
	if !errorResponse.IsResponse() {
		t.Error("expected IsResponse() to return true for error response")
	}
}

func TestNewJSONRPCRequest(t *testing.T) {
	params := map[string]string{"key": "value"}

	msg, err := NewJSONRPCRequest(1, "test/method", params)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if msg.JSONRPC != JSONRPCVersion {
		t.Errorf("expected jsonrpc %s, got %s", JSONRPCVersion, msg.JSONRPC)
	}
	if msg.Method != "test/method" {
		t.Errorf("expected method test/method, got %s", msg.Method)
	}
	if msg.ID == nil {
		t.Error("expected id to be set")
	}
	if msg.Params == nil {
		t.Error("expected params to be set")
	}
}

func TestNewJSONRPCNotification(t *testing.T) {
	msg, err := NewJSONRPCNotification("test/notification", nil)
	if err != nil {
		t.Fatalf("failed to create notification: %v", err)
	}

	if msg.JSONRPC != JSONRPCVersion {
		t.Errorf("expected jsonrpc %s, got %s", JSONRPCVersion, msg.JSONRPC)
	}
	if msg.Method != "test/notification" {
		t.Errorf("expected method test/notification, got %s", msg.Method)
	}
	if msg.ID != nil {
		t.Error("expected id to be nil for notification")
	}
}

func TestNewJSONRPCResponse(t *testing.T) {
	result := map[string]bool{"success": true}

	msg, err := NewJSONRPCResponse(1, result)
	if err != nil {
		t.Fatalf("failed to create response: %v", err)
	}

	if msg.JSONRPC != JSONRPCVersion {
		t.Errorf("expected jsonrpc %s, got %s", JSONRPCVersion, msg.JSONRPC)
	}
	if msg.ID == nil {
		t.Error("expected id to be set")
	}
	if msg.Result == nil {
		t.Error("expected result to be set")
	}
	if msg.Error != nil {
		t.Error("expected error to be nil")
	}
}

func TestNewJSONRPCErrorResponse(t *testing.T) {
	msg, err := NewJSONRPCErrorResponse(1, InternalError, "test error", nil)
	if err != nil {
		t.Fatalf("failed to create error response: %v", err)
	}

	if msg.JSONRPC != JSONRPCVersion {
		t.Errorf("expected jsonrpc %s, got %s", JSONRPCVersion, msg.JSONRPC)
	}
	if msg.ID == nil {
		t.Error("expected id to be set")
	}
	if msg.Result != nil {
		t.Error("expected result to be nil")
	}
	if msg.Error == nil {
		t.Error("expected error to be set")
	}
	if msg.Error.Code != InternalError {
		t.Errorf("expected error code %d, got %d", InternalError, msg.Error.Code)
	}
	if msg.Error.Message != "test error" {
		t.Errorf("expected error message 'test error', got '%s'", msg.Error.Message)
	}
}

func TestJSONRPCError_Error(t *testing.T) {
	err := &JSONRPCError{
		Code:    InvalidParams,
		Message: "invalid parameters",
	}

	errStr := err.Error()
	expected := "JSON-RPC error -32602: invalid parameters"
	if errStr != expected {
		t.Errorf("expected '%s', got '%s'", expected, errStr)
	}
}

func TestJSONRPCMessage_RoundTrip(t *testing.T) {
	// Test that a message can be marshaled and unmarshaled correctly
	original, _ := NewJSONRPCRequest(123, "tools/call", map[string]interface{}{
		"name":      "test_tool",
		"arguments": map[string]string{"arg1": "value1"},
	})

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed JSONRPCMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.JSONRPC != original.JSONRPC {
		t.Errorf("jsonrpc mismatch")
	}
	if parsed.Method != original.Method {
		t.Errorf("method mismatch")
	}
	if !parsed.IsRequest() {
		t.Error("expected parsed message to be a request")
	}
}

func TestInitializeParams_Marshal(t *testing.T) {
	params := InitializeParams{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: Implementation{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed InitializeParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.ProtocolVersion != MCPProtocolVersion {
		t.Errorf("protocol version mismatch")
	}
	if parsed.ClientInfo.Name != "test-client" {
		t.Errorf("client name mismatch")
	}
}

func TestTool_Marshal(t *testing.T) {
	tool := Tool{
		Name:        "test_tool",
		Description: "A test tool",
		InputSchema: json.RawMessage(`{"type": "object", "properties": {"arg1": {"type": "string"}}}`),
	}

	data, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed Tool
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Name != tool.Name {
		t.Errorf("name mismatch")
	}
	if parsed.Description != tool.Description {
		t.Errorf("description mismatch")
	}
}
