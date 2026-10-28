// Package jsonrpc is a strict JSON-RPC 2.0 parser for the MCP messages the
// gateway mediates. It is deliberately stricter than encoding/json: duplicate
// object keys, trailing data, deep nesting and batches are rejected, so the
// gateway never decides on one reading of a message while an upstream acts on
// another.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version = "2.0"

	// MaxMessageBytes bounds a single client message.
	MaxMessageBytes = 1 << 20
	// MaxDepth bounds object/array nesting anywhere in a message.
	MaxDepth = 64
)

// Standard JSON-RPC error codes plus the gateway's own.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	// CodeForbidden is returned when policy or a detector denies a call.
	CodeForbidden = -32003
	// CodeUpstream is returned when an upstream MCP server fails.
	CodeUpstream = -32004
)

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message) }

// Request is a JSON-RPC request or notification (ID == nil).
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request carries no id.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is a JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// NewResult builds a success response.
func NewResult(id json.RawMessage, result any) (*Response, error) {
	b, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Response{JSONRPC: Version, ID: id, Result: b}, nil
}

// NewError builds an error response. A nil id becomes JSON null.
func NewError(id json.RawMessage, e *Error) *Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Response{JSONRPC: Version, ID: id, Error: e}
}

var errDuplicateKey = errors.New("duplicate object key")

// CheckStructure walks a JSON document token by token and rejects duplicate
// keys in any object, nesting deeper than MaxDepth, and trailing data.
func CheckStructure(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walk(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func walk(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > MaxDepth {
		return fmt.Errorf("nesting deeper than %d", MaxDepth)
	}
	switch d {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, ok := kt.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, dup := seen[k]; dup {
				return fmt.Errorf("%w %q", errDuplicateKey, k)
			}
			seen[k] = struct{}{}
			if err := walk(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walk(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", d)
	}
	_, err = dec.Token() // closing delimiter
	return err
}

// ParseRequest parses one client message. The returned *Error is suitable to
// send back to the client as-is.
func ParseRequest(b []byte) (*Request, *Error) {
	if len(b) > MaxMessageBytes {
		return nil, &Error{Code: CodeInvalidRequest, Message: "message too large"}
	}
	trimmed := bytes.TrimLeft(b, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, &Error{Code: CodeParseError, Message: "empty message"}
	}
	if trimmed[0] == '[' {
		// MCP 2025-06-18 removed JSON-RPC batching.
		return nil, &Error{Code: CodeInvalidRequest, Message: "batch requests are not supported"}
	}
	if trimmed[0] != '{' {
		return nil, &Error{Code: CodeInvalidRequest, Message: "message must be a JSON object"}
	}
	if err := CheckStructure(b); err != nil {
		if errors.Is(err, errDuplicateKey) {
			return nil, &Error{Code: CodeInvalidRequest, Message: err.Error()}
		}
		return nil, &Error{Code: CodeParseError, Message: err.Error()}
	}
	// encoding/json matches field names case-insensitively ("pArAms" would
	// fill Params). Check the exact member names first.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Message: "invalid request: " + err.Error()}
	}
	for k := range members {
		switch k {
		case "jsonrpc", "id", "method", "params":
		default:
			return nil, &Error{Code: CodeInvalidRequest, Message: fmt.Sprintf("unknown member %q", k)}
		}
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Message: "invalid request: " + err.Error()}
	}
	if req.JSONRPC != Version {
		return nil, &Error{Code: CodeInvalidRequest, Message: `jsonrpc must be "2.0"`}
	}
	if req.Method == "" {
		return nil, &Error{Code: CodeInvalidRequest, Message: "method is required"}
	}
	if len(req.ID) > 0 {
		if err := validateID(req.ID); err != nil {
			return nil, &Error{Code: CodeInvalidRequest, Message: err.Error()}
		}
	}
	if len(req.Params) > 0 {
		p := bytes.TrimLeft(req.Params, " \t\r\n")
		if p[0] != '{' && p[0] != '[' {
			return nil, &Error{Code: CodeInvalidRequest, Message: "params must be an object or array"}
		}
	}
	return &req, nil
}

// validateID accepts a string or an integer id. MCP forbids null ids.
func validateID(id json.RawMessage) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(id))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return errors.New("invalid id")
	}
	switch t := v.(type) {
	case string:
		return nil
	case json.Number:
		if _, err := t.Int64(); err != nil {
			return errors.New("id must be a string or an integer")
		}
		return nil
	default:
		return errors.New("id must be a string or an integer")
	}
}

// CallParams are the params of tools/call.
type CallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

// ParseCallParams decodes tools/call params. Arguments, when present, must be
// a JSON object; they are returned decoded (numbers as json.Number) so the
// caller can evaluate and re-encode exactly what it evaluated.
func ParseCallParams(raw json.RawMessage) (*CallParams, map[string]any, *Error) {
	if len(raw) == 0 {
		return nil, nil, &Error{Code: CodeInvalidParams, Message: "params are required"}
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, nil, &Error{Code: CodeInvalidParams, Message: "invalid tools/call params: " + err.Error()}
	}
	for k := range members {
		switch k {
		case "name", "arguments", "_meta":
		default:
			return nil, nil, &Error{Code: CodeInvalidParams, Message: fmt.Sprintf("unknown member %q", k)}
		}
	}
	var p CallParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &Error{Code: CodeInvalidParams, Message: "invalid tools/call params: " + err.Error()}
	}
	if p.Name == "" {
		return nil, nil, &Error{Code: CodeInvalidParams, Message: "tool name is required"}
	}
	args := map[string]any{}
	if len(p.Arguments) > 0 && !bytes.Equal(bytes.TrimSpace(p.Arguments), []byte("null")) {
		d := json.NewDecoder(bytes.NewReader(p.Arguments))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			return nil, nil, &Error{Code: CodeInvalidParams, Message: "invalid arguments"}
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, nil, &Error{Code: CodeInvalidParams, Message: "arguments must be an object"}
		}
		args = m
	}
	return &p, args, nil
}

// ParseResponse parses an upstream response.
func ParseResponse(b []byte) (*Response, error) {
	if err := CheckStructure(b); err != nil {
		return nil, err
	}
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.JSONRPC != Version {
		return nil, errors.New(`response jsonrpc must be "2.0"`)
	}
	if r.Error == nil && len(r.Result) == 0 {
		return nil, errors.New("response has neither result nor error")
	}
	return &r, nil
}
