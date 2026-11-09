// Command mcp exposes yarrow over the Model Context Protocol so an agent can
// parse and scan YARA rules as tools. It speaks MCP's stdio transport —
// newline-delimited JSON-RPC 2.0 on stdin/stdout — hand-rolled with encoding/json
// so the example stays stdlib-only (no MCP SDK dependency).
//
// Tools:
//   - yara_parse: parse and validate a rule, returning its rule and import names
//     plus any syntax diagnostics (and, with dump=true, the AST).
//   - yara_scan:  compile rules and scan data, returning the matched rule names.
//
// Point an MCP client at command `go run ./example/mcp`, or drive it by hand:
//
//	printf '%s\n' \
//	  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
//	  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
//	  | go run ./example/mcp
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/netstar-labs/yarrow"
	"github.com/netstar-labs/yarrow/pkg/compile"
)

// protocolVersion is the MCP revision this server implements.
const protocolVersion = "2024-11-05"

// rpcRequest is the subset of a JSON-RPC 2.0 request the transport reads. A
// message with no id is a notification and gets no reply.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	// Rules can be large, so read with a generous buffer rather than a Scanner
	// whose default line cap is 64 KiB. json.Marshal escapes newlines, so one
	// message is always exactly one line.
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for {
		line, err := in.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			handleLine(line, out)
			out.Flush()
		}
		if err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, "mcp: read:", err)
			}
			return
		}
	}
}

func handleLine(line []byte, out *bufio.Writer) {
	var req rpcRequest
	if err := json.Unmarshal(bytes.TrimSpace(line), &req); err != nil {
		writeError(out, nil, &rpcError{Code: -32700, Message: "parse error: " + err.Error()})
		return
	}
	notification := len(req.ID) == 0 || string(req.ID) == "null"
	result, rerr := dispatch(req)
	if notification {
		return // notifications get no response, success or not
	}
	if rerr != nil {
		writeError(out, req.ID, rerr)
		return
	}
	writeResult(out, req.ID, result)
}

func dispatch(req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "yarrow-mcp", "version": "0.2.2"},
		}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs}, nil
	case "tools/call":
		return callTool(req.Params)
	case "ping":
		return map[string]any{}, nil
	case "notifications/initialized", "notifications/cancelled":
		return map[string]any{}, nil // notification: response is suppressed anyway
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
}

// toolDefs is the tool catalogue returned by tools/list. Each entry carries a
// JSON Schema so the client knows how to call it.
var toolDefs = []map[string]any{
	{
		"name":        "yara_parse",
		"description": "Parse and validate a YARA rule. Returns the rule and import names and any syntax diagnostics; set dump=true to also return the AST.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule": map[string]any{"type": "string", "description": "YARA rule source text"},
				"dump": map[string]any{"type": "boolean", "description": "include the AST dump in the result"},
			},
			"required": []string{"rule"},
		},
	},
	{
		"name":        "yara_scan",
		"description": "Compile YARA rules and scan data, returning the names of the rules that matched. Supply the target as text (data) or base64 (data_base64) for binary.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rules":       map[string]any{"type": "string", "description": "YARA rule source text"},
				"data":        map[string]any{"type": "string", "description": "scan target as a UTF-8 string"},
				"data_base64": map[string]any{"type": "string", "description": "scan target as base64 (use for binary)"},
			},
			"required": []string{"rules"},
		},
	},
}

func callTool(params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	switch call.Name {
	case "yara_parse":
		return toolResult(yaraParse(call.Arguments))
	case "yara_scan":
		return toolResult(yaraScan(call.Arguments))
	default:
		return nil, &rpcError{Code: -32602, Message: "unknown tool: " + call.Name}
	}
}

// yaraParse validates a rule. A rule with syntax diagnostics is a normal result
// (ok=false), not a tool failure; only a hard parse error sets isError.
func yaraParse(args json.RawMessage) (string, bool) {
	var a struct {
		Rule string `json:"rule"`
		Dump bool   `json:"dump"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "invalid arguments: " + err.Error(), true
	}
	if a.Rule == "" {
		return "missing required argument: rule", true
	}
	ast, err := yarrow.ParseAST([]byte(a.Rule))
	if err != nil {
		return "parse: " + err.Error(), true
	}
	rules, imports := []string{}, []string{}
	for _, it := range ast.Items {
		switch v := it.(type) {
		case *yarrow.Rule:
			rules = append(rules, v.Identifier.Name)
		case *yarrow.Import:
			imports = append(imports, v.Module)
		}
	}
	diags := make([]map[string]any, 0, len(ast.Errors))
	for _, d := range ast.Errors {
		diags = append(diags, map[string]any{"message": d.Message, "start": d.Span.Start, "end": d.Span.End})
	}
	res := map[string]any{
		"ok":      len(ast.Errors) == 0,
		"rules":   rules,
		"imports": imports,
		"errors":  diags,
	}
	if a.Dump {
		res["ast"] = ast.String()
	}
	return jsonString(res), false
}

func yaraScan(args json.RawMessage) (string, bool) {
	var a struct {
		Rules      string `json:"rules"`
		Data       string `json:"data"`
		DataBase64 string `json:"data_base64"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "invalid arguments: " + err.Error(), true
	}
	if a.Rules == "" {
		return "missing required argument: rules", true
	}
	data := []byte(a.Data)
	if a.DataBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(a.DataBase64)
		if err != nil {
			return "data_base64: " + err.Error(), true
		}
		data = b
	}
	rs, err := compile.Compile([]byte(a.Rules))
	if err != nil {
		return "compile: " + err.Error(), true
	}
	matches, err := rs.Scan(data)
	if err != nil {
		return "scan: " + err.Error(), true
	}
	if matches == nil {
		matches = []string{}
	}
	return jsonString(map[string]any{"matches": matches, "count": len(matches)}), false
}

// toolResult wraps a tool's text output in the MCP content envelope. A tool-level
// failure travels as isError inside the result — not as a JSON-RPC error — so the
// model still sees the message.
func toolResult(text string, isErr bool) (any, *rpcError) {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}, nil
}

func writeResult(out *bufio.Writer, id json.RawMessage, result any) {
	writeRaw(out, map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "result": result})
}

func writeError(out *bufio.Writer, id json.RawMessage, e *rpcError) {
	writeRaw(out, map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "error": e})
}

func writeRaw(out *bufio.Writer, msg any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	out.Write(b)
	out.WriteByte('\n')
}

func rawOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func jsonString(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("marshal error: %v", err)
	}
	return string(b)
}
