package yarrow

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// checkInvariants verifies the properties that must hold for every parse,
// valid input or not. These are what make the tree trustworthy downstream:
//
//   - Losslessness. The token spans tile the source exactly: no gaps, no
//     overlaps, nothing past the end. A formatter can therefore rebuild the
//     input byte for byte, and no input can be silently dropped.
//   - Balance. Every Begin has a matching End, so the event stream always
//     forms a tree.
//   - Well-formed spans. No span runs backwards or past the source.
//
// A parser that merely "doesn't crash" can still violate all of these, which
// is why the corpus run checks them rather than just exit status.
func checkInvariants(src []byte, events []Event) error {
	var (
		depth int
		pos   uint32
		kinds []SyntaxKind
	)
	for i, ev := range events {
		if ev.Span.End < ev.Span.Start {
			return fmt.Errorf("event %d (%v): span runs backwards %d..%d",
				i, ev.Kind, ev.Span.Start, ev.Span.End)
		}
		if int(ev.Span.End) > len(src) {
			return fmt.Errorf("event %d (%v): span %d..%d past end of %d-byte source",
				i, ev.Kind, ev.Span.Start, ev.Span.End, len(src))
		}
		switch ev.Kind {
		case EventBegin:
			depth++
			kinds = append(kinds, ev.Syntax)
		case EventEnd:
			depth--
			if depth < 0 {
				return fmt.Errorf("event %d: End without Begin", i)
			}
			if got, want := ev.Syntax, kinds[len(kinds)-1]; got != want {
				return fmt.Errorf("event %d: End %v closes Begin %v", i, got, want)
			}
			kinds = kinds[:len(kinds)-1]
		case EventToken:
			if ev.Span.Start != pos {
				return fmt.Errorf("event %d: token at %d..%d leaves %d..%d uncovered",
					i, ev.Span.Start, ev.Span.End, pos, ev.Span.Start)
			}
			pos = ev.Span.End
		}
	}
	if depth != 0 {
		return fmt.Errorf("%d unclosed node(s)", depth)
	}
	if pos != uint32(len(src)) {
		return fmt.Errorf("tokens cover %d of %d bytes", pos, len(src))
	}
	return nil
}

// TestInvariantsOnGoldens checks the invariants on the reference corpus,
// including its deliberately malformed cases.
func TestInvariantsOnGoldens(t *testing.T) {
	for _, name := range goldenCases(t) {
		t.Run(name, func(t *testing.T) {
			src := []byte(read(t, "testdata/parser/"+name+".in"))
			if err := checkInvariants(src, NewParser(src).Events()); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// TestCorpus runs the parser over a directory tree of real rule files.
//
// Set YARA_CORPUS to enable it. This is kept out of the default run because
// it needs a corpus that is not vendored into the repository.
func TestCorpus(t *testing.T) {
	root := os.Getenv("YARA_CORPUS")
	if root == "" {
		t.Skip("set YARA_CORPUS to a directory of .yar files to run")
	}

	var (
		files, clean, withErrors int
		bytes                    int64
		broken                   []string
		errFreq                  = map[string]int{}
	)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yar", ".yara":
		default:
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files++
		bytes += int64(len(src))

		events := NewParser(src).Events()
		if err := checkInvariants(src, events); err != nil {
			broken = append(broken, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		cst := BuildCST(events, src)
		if len(cst.Errors) == 0 {
			clean++
		} else {
			withErrors++
			// Record the message shape so systematic gaps stand out from
			// one-off malformed files.
			errFreq[normaliseMessage(cst.Errors[0].Message)]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	t.Logf("files=%d bytes=%d clean=%d with-errors=%d invariant-violations=%d",
		files, bytes, clean, withErrors, len(broken))

	for _, b := range broken {
		t.Errorf("invariant violation: %s", b)
	}

	type kv struct {
		msg string
		n   int
	}
	var top []kv
	for m, n := range errFreq {
		top = append(top, kv{m, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	for i, e := range top {
		if i == 15 {
			break
		}
		t.Logf("  %4d x %s", e.n, e.msg)
	}
}

// normaliseMessage strips the quoted offending text so that messages differing
// only in that text group together.
func normaliseMessage(m string) string {
	if i := strings.Index(m, ", found `"); i >= 0 {
		return m[:i] + ", found ..."
	}
	return m
}

// TestASTCorpus lowers every corpus file to an AST and checks that lowering
// is total: it must not panic, and it must render without error. A rule the
// parser accepts should always lower, so any drop here is a real gap in the
// builder rather than bad input.
func TestASTCorpus(t *testing.T) {
	root := os.Getenv("YARA_CORPUS")
	if root == "" {
		t.Skip("set YARA_CORPUS to run")
	}
	var files, rules, lowered, dropped int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yar", ".yara":
		default:
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files++
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic during lowering: %v", path, r)
				}
			}()
			events := NewParser(src).Events()
			// Count CST rules so we can tell how many should have lowered.
			for _, ev := range events {
				if ev.Kind == EventBegin && ev.Syntax == RULE_DECL {
					rules++
				}
			}
			ast := BuildAST(events, src)
			for _, it := range ast.Items {
				if _, ok := it.(*Rule); ok {
					lowered++
				}
			}
			_ = ast.String() // must not panic
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	dropped = rules - lowered
	t.Logf("files=%d cst-rules=%d lowered-rules=%d dropped=%d", files, rules, lowered, dropped)
	if dropped != 0 {
		t.Errorf("%d rules parsed but failed to lower", dropped)
	}
}
