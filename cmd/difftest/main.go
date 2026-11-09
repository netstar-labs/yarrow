// Command difftest is the differential-testing harness: it runs yarrow and the
// real YARA-X parser over the same corpus and diffs their dumps byte-for-byte,
// rather than relying on the fixed golden set. Any construct the goldens do not
// exercise but the corpus does will surface here as a divergence.
//
//	go build -o difftest ./cmd/difftest
//	difftest -corpus _corpus -ref _ref/yara-x/target/release/examples/dump
//
// The reference side is a small harness built against YARA-X at the pinned
// REFERENCE_COMMIT (see _ref/yara-x/parser/examples/dump.rs). The Go side is the
// yarrow library, called in-process. Exit status is 1 if any divergence is found.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/netstar-labs/yarrow"
)

func main() { os.Exit(run()) }

type result struct {
	file, mode string
	kind       string // "match" | "mismatch" | "yarrow-error" | "ref-error"
	detail     string // for mismatch: a compact first-divergence diff; for errors: the message
}

func run() int {
	corpus := flag.String("corpus", "_corpus", "root directory of the rule corpus (walked for *.yar/*.yara)")
	ref := flag.String("ref", "_ref/yara-x/target/release/examples/dump", "path to the YARA-X reference dump binary")
	modesArg := flag.String("modes", "cst,cststream,ast", "comma-separated modes to diff")
	jobs := flag.Int("jobs", runtime.NumCPU(), "parallel workers")
	maxReport := flag.Int("max-report", 15, "max divergent (file,mode) pairs to print in detail")
	flag.Parse()

	if _, err := os.Stat(*ref); err != nil {
		fmt.Fprintf(os.Stderr, "difftest: reference binary %q not found: %v\n", *ref, err)
		return 2
	}
	modes := strings.Split(*modesArg, ",")

	files, err := collectRules(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "difftest:", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "difftest: no *.yar/*.yara files under %q\n", *corpus)
		return 2
	}
	fmt.Printf("corpus: %d files × %d modes = %d comparisons (%d workers)\n",
		len(files), len(modes), len(files)*len(modes), *jobs)

	var (
		results []result
		mu      sync.Mutex
		done    atomic.Int64
		fileCh  = make(chan string)
		wg      sync.WaitGroup
	)
	for w := 0; w < *jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range fileCh {
				local := compareFile(f, *ref, modes)
				mu.Lock()
				results = append(results, local...)
				mu.Unlock()
				if n := done.Add(1); n%200 == 0 {
					fmt.Printf("  … %d/%d files\n", n, len(files))
				}
			}
		}()
	}
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)
	wg.Wait()

	return report(results, modes, len(files), *maxReport)
}

// compareFile runs every mode for one file and returns a result per mode.
func compareFile(file, ref string, modes []string) []result {
	src, err := os.ReadFile(file)
	if err != nil {
		return []result{{file: file, mode: "-", kind: "yarrow-error", detail: "read: " + err.Error()}}
	}
	out := make([]result, 0, len(modes))
	for _, mode := range modes {
		got, gerr := yarrowDump(mode, src)
		if gerr != nil {
			out = append(out, result{file, mode, "yarrow-error", gerr.Error()})
			continue
		}
		want, rerr := refDump(ref, mode, file)
		if rerr != nil {
			out = append(out, result{file, mode, "ref-error", rerr.Error()})
			continue
		}
		if got == want {
			out = append(out, result{file, mode, "match", ""})
		} else {
			out = append(out, result{file, mode, "mismatch", firstDivergence(want, got)})
		}
	}
	return out
}

// yarrowDump renders one mode in-process, recovering any panic (itself a finding)
// so one bad file cannot abort the whole sweep.
func yarrowDump(mode string, src []byte) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = "", fmt.Errorf("panic: %v", r)
		}
	}()
	switch mode {
	case "cst":
		cst, e := yarrow.Parse(src)
		if e != nil {
			return "", e
		}
		return cst.String(), nil
	case "cststream":
		return yarrow.FormatEvents(yarrow.NewParser(src).Events()), nil
	case "ast":
		ast, e := yarrow.ParseAST(src)
		if e != nil {
			return "", e
		}
		return ast.String(), nil
	default:
		return "", fmt.Errorf("unknown mode %q", mode)
	}
}

// refDump execs the reference binary for one mode. A non-zero exit (e.g. the
// reference's CST::try_from failing) is returned as an error, categorised
// separately from a genuine content mismatch.
func refDump(ref, mode, file string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(ref, "-mode", mode, file)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}

// firstDivergence returns a compact report of the first line where want (ref) and
// got (yarrow) differ, with a little context.
func firstDivergence(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	n := len(wl)
	if len(gl) < n {
		n = len(gl)
	}
	for i := 0; i < n; i++ {
		if wl[i] != gl[i] {
			var b strings.Builder
			lo := i - 2
			if lo < 0 {
				lo = 0
			}
			for j := lo; j < i; j++ {
				fmt.Fprintf(&b, "      %d  %s\n", j+1, wl[j])
			}
			fmt.Fprintf(&b, "  ref %d  %s\n", i+1, wl[i])
			fmt.Fprintf(&b, "  got %d  %s\n", i+1, gl[i])
			return b.String()
		}
	}
	// No differing line within the shared prefix → one side is longer.
	return fmt.Sprintf("  identical for %d lines, then lengths differ: ref=%d lines, yarrow=%d lines\n",
		n, len(wl), len(gl))
}

func collectRules(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext == ".yar" || ext == ".yara" {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

// report prints the per-mode tally and the first maxReport divergences, and
// returns the process exit code (1 if any mismatch).
func report(results []result, modes []string, nFiles, maxReport int) int {
	type tally struct{ match, mismatch, yarrowErr, refErr int }
	byMode := map[string]*tally{}
	for _, m := range modes {
		byMode[m] = &tally{}
	}
	var mismatches, yarrowErrs []result
	for _, r := range results {
		t := byMode[r.mode]
		switch r.kind {
		case "match":
			t.match++
		case "mismatch":
			t.mismatch++
			mismatches = append(mismatches, r)
		case "yarrow-error":
			if t != nil {
				t.yarrowErr++
			}
			yarrowErrs = append(yarrowErrs, r)
		case "ref-error":
			if t != nil {
				t.refErr++
			}
		}
	}

	fmt.Printf("\n=== differential results (%d files) ===\n", nFiles)
	fmt.Printf("%-12s %8s %8s %11s %9s\n", "mode", "match", "MISMATCH", "yarrow-err", "ref-err")
	totalMismatch := 0
	for _, m := range modes {
		t := byMode[m]
		fmt.Printf("%-12s %8d %8d %11d %9d\n", m, t.match, t.mismatch, t.yarrowErr, t.refErr)
		totalMismatch += t.mismatch
	}

	sort.Slice(mismatches, func(i, j int) bool {
		if mismatches[i].file != mismatches[j].file {
			return mismatches[i].file < mismatches[j].file
		}
		return mismatches[i].mode < mismatches[j].mode
	})
	if totalMismatch > 0 {
		fmt.Printf("\n=== first %d of %d divergences ===\n", min(maxReport, totalMismatch), totalMismatch)
		for i, r := range mismatches {
			if i >= maxReport {
				break
			}
			fmt.Printf("\n[%s]  %s\n%s", r.mode, r.file, r.detail)
		}
	}
	// yarrow-error is usually a deliberate safety guard (e.g. size limit); surface
	// it but do not fail on it unless it is unexpected.
	if len(yarrowErrs) > 0 {
		fmt.Printf("\n%d yarrow-error case(s) (first 5):\n", len(yarrowErrs))
		for i, r := range yarrowErrs {
			if i >= 5 {
				break
			}
			fmt.Printf("  [%s] %s: %s\n", r.mode, r.file, r.detail)
		}
	}

	if totalMismatch == 0 {
		fmt.Println("\nNO DIVERGENCES — yarrow matches YARA-X byte-for-byte across the corpus.")
		return 0
	}
	fmt.Printf("\n%d DIVERGENCE(S) found.\n", totalMismatch)
	return 1
}
