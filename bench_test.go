package yarrow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchSource is a synthetic rule file exercising the constructs that
// dominate real corpora: text patterns, hex patterns with jumps and
// alternatives, regexps, metadata, and a condition with arithmetic and
// quantifiers.
const benchSource = `
import "pe"
import "math"

rule Bench_Alpha : trojan banker {
    meta:
        author = "R&D"
        description = "benchmark rule with a reasonably long description field"
        threat_level = 5
        accuracy = 0.95
        in_the_wild = true
    strings:
        $s1 = "UVODFRYSIHLNWPEJXQZAKCBGMT" ascii wide nocase
        $s2 = "another literal string here" fullword
        $s3 = { 6A 40 68 00 30 00 00 6A 14 8D 91 [4-8] FF ?? ~AB }
        $s4 = { (61 62 | 63 64 65) [2-] 90 90 [-] FF }
        $r1 = /foo[0-9]{2,4}bar.*baz/is
        $b1 = "encoded" base64("!@#$%^&*(){}[.,|-_=+~ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        $x1 = "xored" xor(0-255)
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        pe.number_of_sections > 3 and
        math.entropy(0, filesize) >= 7.0 and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size % 512 == 0
        ) and
        2 of ($s*) and
        any of ($r1, $b1) and
        ($s1 at pe.entry_point or $s2 in (0..1024))
}

rule Bench_Beta {
    condition:
        Bench_Alpha and not (filesize > 1MB and filesize < 10MB)
}
`

// corpusBlob concatenates the corpus into one buffer, or returns nil when
// YARA_CORPUS is unset. Benchmarking on real rules matters because synthetic
// input under-represents comments and long metadata.
func corpusBlob() []byte {
	root := os.Getenv("YARA_CORPUS")
	if root == "" {
		return nil
	}
	var b []byte
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
		b = append(b, src...)
		b = append(b, '\n')
		return nil
	})
	return b
}

func BenchmarkTokenize(b *testing.B) {
	src := []byte(benchSource)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tz := NewTokenizer(src)
		for {
			if _, ok := tz.Next(); !ok {
				break
			}
		}
	}
}

func BenchmarkParseEvents(b *testing.B) {
	src := []byte(benchSource)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewParser(src).Events()
	}
}

func BenchmarkParseCST(b *testing.B) {
	src := []byte(benchSource)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(src); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenizeCorpus(b *testing.B) {
	src := corpusBlob()
	if src == nil {
		b.Skip("set YARA_CORPUS")
	}
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tz := NewTokenizer(src)
		for {
			if _, ok := tz.Next(); !ok {
				break
			}
		}
	}
}
