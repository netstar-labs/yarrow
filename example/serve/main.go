// Command serve is a library-embed demo that exposes yarrow's matcher as a small
// scan service over HTTP and/or a Unix domain socket. The rule set is compiled
// once at startup; each request POSTs the bytes to scan to /scan and gets back
// the names of the rules that matched, as JSON.
//
//	go run ./example/serve -rules rules.yar -http :8080
//	go run ./example/serve -rules rules.yar -unix /tmp/yarrow.sock
//	go run ./example/serve -rules rules.yar -http :8080 -unix /tmp/yarrow.sock
//
// Scan a target against it:
//
//	curl --data-binary @sample.bin http://localhost:8080/scan
//	curl --data-binary @sample.bin --unix-socket /tmp/yarrow.sock http://x/scan
//
// It is deliberately stdlib-only — net/http and net — so putting yarrow behind a
// transport adds no dependencies to the module.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/netstar-labs/yarrow/pkg/compile"
)

func main() {
	rulesPath := flag.String("rules", "", "path to the YARA rule file to compile (required)")
	httpAddr := flag.String("http", "", "TCP address to serve HTTP on, e.g. :8080")
	unixPath := flag.String("unix", "", "path to a Unix domain socket to serve on")
	maxBytes := flag.Int64("max-bytes", 32<<20, "reject scan bodies larger than this many bytes")
	flag.Parse()

	if *rulesPath == "" || (*httpAddr == "" && *unixPath == "") {
		log.Println("serve: -rules and at least one of -http/-unix are required")
		flag.Usage()
		os.Exit(2)
	}

	// Compile once. The hot path below only runs Scan, never Compile.
	src, err := os.ReadFile(*rulesPath)
	if err != nil {
		log.Fatalf("serve: %v", err)
	}
	rs, err := compile.Compile(src)
	if err != nil {
		log.Fatalf("serve: compile: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/scan", scanHandler(rs, *maxBytes))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	})

	// One handler, one or two listeners. The first listener to fail ends the
	// program.
	errc := make(chan error, 2)

	if *httpAddr != "" {
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			log.Fatalf("serve: http listen: %v", err)
		}
		log.Printf("serving HTTP on %s", ln.Addr())
		go func() { errc <- http.Serve(ln, mux) }()
	}

	if *unixPath != "" {
		// A stale socket from a previous run blocks Listen; this process owns
		// the path, so clear it first and remove it again on a clean exit.
		_ = os.Remove(*unixPath)
		ln, err := net.Listen("unix", *unixPath)
		if err != nil {
			log.Fatalf("serve: unix listen: %v", err)
		}
		log.Printf("serving on unix socket %s", *unixPath)
		go func() { errc <- http.Serve(ln, mux) }()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sig
			os.Remove(*unixPath)
			os.Exit(0)
		}()
	}

	log.Fatal(<-errc)
}

// scanHandler closes over the pre-compiled RuleSet so a request only runs Scan.
// The request body is the raw bytes to scan; the reply is the matched rule names.
func scanHandler(rs *compile.RuleSet, maxBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST with the scan target as the request body", http.StatusMethodNotAllowed)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		matches, err := rs.Scan(data)
		if err != nil {
			http.Error(w, "scan: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if matches == nil {
			matches = []string{} // encode an empty result as [], not null
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"matches": matches,
			"count":   len(matches),
		})
	}
}
