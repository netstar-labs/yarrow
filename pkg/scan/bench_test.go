package scan

import (
	"bytes"
	"testing"
)

func benchData(n int) []byte {
	b := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), n/45+1)
	return b[:n]
}

func BenchmarkLiteral4K(b *testing.B) {
	p := Literal([]byte("malware"), false)
	data := benchData(4096)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.FindAll(data)
	}
}

func BenchmarkRegexp4K(b *testing.B) {
	p, _ := Regexp("qu[a-z]+k", false, false)
	data := benchData(4096)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.FindAll(data)
	}
}

func BenchmarkHex4K(b *testing.B) {
	p, _ := Compile([]Element{Byte('f'), Byte('o'), Byte('x'), Jump{Min: 1, Max: 6}, Byte('j')})
	data := benchData(4096)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.FindAll(data)
	}
}

// BenchmarkTextLiteral4K measures the plain-literal fast path (bytes.Index) used
// by pkg/compile for un-modified text patterns.
func BenchmarkTextLiteral4K(b *testing.B) {
	p := CompileText([]byte("malware"), TextMods{})
	data := benchData(4096)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.FindAll(data)
	}
}
