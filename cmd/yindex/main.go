// Command yindex builds a metadata index of the aggregated public YARA rule
// corpus (resources/corpus/, populated by resources/fetch.sh). It parses every
// rule with yarrow itself — so the run doubles as a parser validation over the
// whole public corpus — and writes:
//
//   - resources/index.jsonl        one JSON object per rule (metadata only)
//   - resources/index.summary.json aggregate stats + per-source + parse health
//
// Only derived metadata is emitted (rule name, tags, imports, counts, flags,
// parse status) — never the rule bodies / detection logic.
//
//	go run ./cmd/yindex   # after: bash resources/fetch.sh
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/netstar-labs/yarrow"
)

func main() { os.Exit(run()) }

type source struct {
	Name        string `json:"name"`
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	License     string `json:"license"`
	Description string `json:"description"`
}

// ruleEntry is one indexed rule (metadata only).
type ruleEntry struct {
	Source  string   `json:"source"`
	File    string   `json:"file"`
	Rule    string   `json:"rule"`
	Tags    []string `json:"tags,omitempty"`
	Imports []string `json:"imports,omitempty"`
	Strings int      `json:"strings"`
	Private bool     `json:"private,omitempty"`
	Global  bool     `json:"global,omitempty"`
}

func run() int {
	sourcesPath := "resources/sources.json"
	corpusRoot := "resources/corpus"
	outPath := "resources/index.jsonl"
	summaryPath := "resources/index.summary.json"

	raw, err := os.ReadFile(sourcesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yindex:", err)
		return 2
	}
	var manifest struct {
		Sources []source `json:"sources"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		fmt.Fprintln(os.Stderr, "yindex: sources.json:", err)
		return 2
	}

	var (
		all    []ruleEntry
		perSrc = map[string]*srcStat{}
		mu     sync.Mutex
	)
	for _, s := range manifest.Sources {
		st := &srcStat{Name: s.Name, License: s.License, Description: s.Description}
		perSrc[s.Name] = st
		dir := filepath.Join(corpusRoot, s.Name, s.Path)
		files := collectRuleFiles(dir)
		st.Files = len(files)
		if len(files) == 0 {
			continue
		}
		indexFiles(s.Name, corpusRoot, files, st, func(es []ruleEntry) {
			mu.Lock()
			all = append(all, es...)
			mu.Unlock()
		})
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Source != all[j].Source {
			return all[i].Source < all[j].Source
		}
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Rule < all[j].Rule
	})

	if err := writeJSONL(outPath, all); err != nil {
		fmt.Fprintln(os.Stderr, "yindex:", err)
		return 1
	}
	if err := writeSummary(summaryPath, manifest.Sources, perSrc, all); err != nil {
		fmt.Fprintln(os.Stderr, "yindex:", err)
		return 1
	}

	var files, rules, clean, errf int
	for _, st := range perSrc {
		files += st.Files
		rules += st.Rules
		clean += st.CleanFiles
		errf += st.ErrorFiles
	}
	fmt.Printf("indexed %d rules across %d files (%d clean, %d with syntax errors) from %d sources\n",
		rules, files, clean, errf, len(manifest.Sources))
	fmt.Printf("wrote %s and %s\n", outPath, summaryPath)
	return 0
}

type srcStat struct {
	Name        string `json:"name"`
	License     string `json:"license"`
	Description string `json:"description"`
	Files       int    `json:"files"`
	Rules       int    `json:"rules"`
	CleanFiles  int    `json:"clean_files"`
	ErrorFiles  int    `json:"error_files"`
}

// indexFiles parses each file with yarrow (in parallel) and feeds rule entries to
// emit; it updates st's counters under its own lock.
func indexFiles(srcName, corpusRoot string, files []string, st *srcStat, emit func([]ruleEntry)) {
	var stMu sync.Mutex
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()
			rel, _ := filepath.Rel(filepath.Join(corpusRoot, srcName), f)
			entries, clean := parseFile(srcName, rel, f)
			stMu.Lock()
			st.Rules += len(entries)
			if clean {
				st.CleanFiles++
			} else {
				st.ErrorFiles++
			}
			stMu.Unlock()
			if len(entries) > 0 {
				emit(entries)
			}
		}(f)
	}
	wg.Wait()
}

// parseFile parses one rule file with yarrow and returns its rule entries plus
// whether it parsed with no syntax errors. A parse panic (should never happen —
// the parser is fuzzed) is recovered so one file cannot abort the index.
func parseFile(srcName, rel, path string) (entries []ruleEntry, clean bool) {
	defer func() {
		if recover() != nil {
			entries, clean = nil, false
		}
	}()
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	ast, err := yarrow.ParseAST(src)
	if err != nil {
		return nil, false
	}
	clean = len(ast.Errors) == 0

	var imports []string
	for _, item := range ast.Items {
		if imp, ok := item.(*yarrow.Import); ok {
			imports = append(imports, imp.Module)
		}
	}
	sort.Strings(imports)
	for _, item := range ast.Items {
		r, ok := item.(*yarrow.Rule)
		if !ok {
			continue
		}
		e := ruleEntry{
			Source:  srcName,
			File:    filepath.ToSlash(rel),
			Rule:    r.Identifier.Name,
			Imports: imports,
			Strings: len(r.Patterns),
			Private: r.Flags.Has(yarrow.FlagPrivate),
			Global:  r.Flags.Has(yarrow.FlagGlobal),
		}
		for _, t := range r.Tags {
			e.Tags = append(e.Tags, t.Name)
		}
		entries = append(entries, e)
	}
	return entries, clean
}

func collectRuleFiles(root string) []string {
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// .rule is used by some sources (e.g. InQuest) for YARA rules; a non-YARA
		// .rule file simply parses with errors and is counted, not indexed.
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yar", ".yara", ".rule":
			files = append(files, p)
		}
		return nil
	})
	return files
}

func writeJSONL(path string, entries []ruleEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(&e); err != nil {
			return err
		}
	}
	return nil
}

func writeSummary(path string, sources []source, perSrc map[string]*srcStat, all []ruleEntry) error {
	imports := map[string]int{}
	tags := map[string]int{}
	var private, global int
	for _, e := range all {
		for _, im := range e.Imports {
			imports[im]++
		}
		for _, t := range e.Tags {
			tags[t]++
		}
		if e.Private {
			private++
		}
		if e.Global {
			global++
		}
	}

	orderedSrc := make([]*srcStat, 0, len(sources))
	var files, rules, clean, errf int
	for _, s := range sources {
		st := perSrc[s.Name]
		orderedSrc = append(orderedSrc, st)
		files += st.Files
		rules += st.Rules
		clean += st.CleanFiles
		errf += st.ErrorFiles
	}
	pct := 0.0
	if clean+errf > 0 {
		pct = 100 * float64(clean) / float64(clean+errf)
	}

	summary := map[string]any{
		"note":    "Derived metadata only. Rule bodies are not vendored; see resources/README.md. Regenerate with `go run ./cmd/yindex`.",
		"sources": orderedSrc,
		"totals": map[string]any{
			"sources":           len(sources),
			"files":             files,
			"rules":             rules,
			"clean_files":       clean,
			"error_files":       errf,
			"parse_success_pct": round2(pct),
			"rules_private":     private,
			"rules_global":      global,
		},
		"imports":  imports,
		"top_tags": topN(tags, 40),
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

type tagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

func topN(m map[string]int, n int) []tagCount {
	out := make([]tagCount, 0, len(m))
	for k, v := range m {
		out = append(out, tagCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tag < out[j].Tag
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
