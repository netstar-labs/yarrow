# Examples

Every example is stdlib-only, so none of them add a dependency to the module.

| Example | What it shows | Run |
|---|---|---|
| [parse/](parse/main.go) | Library embed: parse a rule and print the CST, the AST, and the raw event stream, plus how to read syntax diagnostics. | `go run ./example/parse` |
| [serve/](serve/main.go) | The matcher as a scan service over HTTP and/or a Unix socket: compile rules once, `POST /scan` the bytes to scan, get matched rule names back as JSON. | `go run ./example/serve -rules rules.yar -http :8080` |
| [mcp/](mcp/main.go) | yarrow as an MCP server (hand-rolled JSON-RPC 2.0 over stdio), exposing `yara_parse` and `yara_scan` tools to an agent. | `go run ./example/mcp` |

## serve

```
go run ./example/serve -rules rules.yar -http :8080          # HTTP
go run ./example/serve -rules rules.yar -unix /tmp/s.sock     # Unix socket
go run ./example/serve -rules rules.yar -http :8080 -unix /tmp/s.sock  # both

curl --data-binary @sample.bin http://localhost:8080/scan
curl --data-binary @sample.bin --unix-socket /tmp/s.sock http://x/scan
# => {"count":1,"matches":["demo"]}
```

## mcp

Newline-delimited JSON-RPC 2.0 on stdin/stdout. Drive it by hand:

```
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | go run ./example/mcp
```

Or register it with an MCP client using the command `go run ./example/mcp`. Binary
scan targets go in `data_base64`; text can use `data`.

For a command-line tool over files or stdin, use the app instead of an example:

```
go run ./app/yarrow                rules.yar     # CST tree (default)
go run ./app/yarrow -mode cststream rules.yar    # flat event stream
go run ./app/yarrow -mode ast       rules.yar    # semantic AST tree
cat rules.yar | go run ./app/yarrow -mode ast    # stdin
```
