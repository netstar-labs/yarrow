package compile

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"hash/crc32"
	"math"
)

// loadModules builds the object for each imported module, bound to the scanned
// data. A module whose format does not match the data (e.g. pe over a non-PE
// file) still yields an object; its fields are simply undefined, matching YARA.
// This is the MVP surface — hash/math functions and the common pe/elf scalar
// fields + sections; full field/constant coverage is a differential-validated
// follow-up (the exact names and enum values are best pinned against YARA-X).
func loadModules(imports []string, data []byte) map[string]value {
	out := make(map[string]value, len(imports))
	for _, name := range imports {
		switch name {
		case "hash":
			out["hash"] = hashModule(data)
		case "math":
			out["math"] = mathModule(data)
		case "pe":
			out["pe"] = peModule(data)
		case "elf":
			out["elf"] = elfModule(data)
			// other modules: left unregistered → a clear "unimported module" error.
		}
	}
	return out
}

// sliceArg resolves a (offset, size) argument pair to a data slice, bounds-checked.
func sliceArg(data []byte, args []value) ([]byte, bool) {
	if len(args) != 2 || args[0].kind != 'i' || args[1].kind != 'i' {
		return nil, false
	}
	off, size := args[0].i, args[1].i
	// Check bounds WITHOUT summing: off+size can overflow int64 (a crafted rule
	// like hash.md5(1<<62, 1<<62) wraps to a negative that passes a naive
	// `off+size > len` guard, then panics the slice).
	if off < 0 || size < 0 || off > int64(len(data)) || size > int64(len(data))-off {
		return nil, false
	}
	return data[off : off+size], true
}

// overSlice adapts a byte-slice function into a module callable: it resolves the
// (offset, size) argument pair via sliceArg (undefined on a bad slice) and maps
// the bytes with f. Every hash/math function that folds a data range is built
// from it, so the bounds-checking contract lives in one place.
func overSlice(data []byte, f func([]byte) value) func([]value) (value, error) {
	return func(args []value) (value, error) {
		b, ok := sliceArg(data, args)
		if !ok {
			return undef(), nil
		}
		return f(b), nil
	}
}

func hashModule(data []byte) value {
	hexOf := func(sum func([]byte) []byte) func([]value) (value, error) {
		return overSlice(data, func(b []byte) value { return vStr(hex.EncodeToString(sum(b))) })
	}
	return vObj(map[string]value{
		"md5":    vCall(hexOf(func(b []byte) []byte { s := md5.Sum(b); return s[:] })),
		"sha1":   vCall(hexOf(func(b []byte) []byte { s := sha1.Sum(b); return s[:] })),
		"sha256": vCall(hexOf(func(b []byte) []byte { s := sha256.Sum256(b); return s[:] })),
		"crc32":  vCall(overSlice(data, func(b []byte) value { return vInt(int64(crc32.ChecksumIEEE(b))) })),
		"checksum32": vCall(overSlice(data, func(b []byte) value {
			var s uint32
			for _, c := range b {
				s += uint32(c)
			}
			return vInt(int64(s))
		})),
	})
}

func mathModule(data []byte) value {
	return vObj(map[string]value{
		"entropy": vCall(overSlice(data, func(b []byte) value { return vFloat(shannon(b)) })),
		"mean": vCall(overSlice(data, func(b []byte) value {
			if len(b) == 0 {
				return undef()
			}
			var sum int64
			for _, c := range b {
				sum += int64(c)
			}
			return vFloat(float64(sum) / float64(len(b)))
		})),
		"min": vCall(func(args []value) (value, error) { return minMax(args, false) }),
		"max": vCall(func(args []value) (value, error) { return minMax(args, true) }),
		"in_range": vCall(func(args []value) (value, error) {
			if len(args) != 3 {
				return undef(), nil
			}
			v, lo, hi, ok := f3(args)
			if !ok {
				return undef(), nil
			}
			return vBool(v >= lo && v <= hi), nil
		}),
	})
}

// minMax returns the min or max of two integer arguments (YARA math.min/max).
func minMax(args []value, wantMax bool) (value, error) {
	if len(args) != 2 || args[0].kind != 'i' || args[1].kind != 'i' {
		return undef(), nil
	}
	a, b := args[0].i, args[1].i
	if wantMax {
		if a > b {
			return vInt(a), nil
		}
		return vInt(b), nil
	}
	if a < b {
		return vInt(a), nil
	}
	return vInt(b), nil
}

func f3(args []value) (a, b, c float64, ok bool) {
	af, aok := args[0].asFloat()
	bf, bok := args[1].asFloat()
	cf, cok := args[2].asFloat()
	return af, bf, cf, aok && bok && cok
}

// shannon returns the Shannon entropy (0..8 bits) of a byte slice.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

func peModule(data []byte) value {
	fields := map[string]value{}
	if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
		fields["number_of_sections"] = vInt(int64(len(f.Sections)))
		fields["machine"] = vInt(int64(f.Machine))
		fields["timestamp"] = vInt(int64(f.FileHeader.TimeDateStamp))
		fields["characteristics"] = vInt(int64(f.FileHeader.Characteristics))
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			fields["entry_point"] = vInt(int64(oh.AddressOfEntryPoint))
			fields["image_base"] = vInt(int64(oh.ImageBase))
			fields["subsystem"] = vInt(int64(oh.Subsystem))
		case *pe.OptionalHeader64:
			fields["entry_point"] = vInt(int64(oh.AddressOfEntryPoint))
			fields["image_base"] = vInt(int64(oh.ImageBase))
			fields["subsystem"] = vInt(int64(oh.Subsystem))
		}
		secs := make([]value, 0, len(f.Sections))
		for _, s := range f.Sections {
			secs = append(secs, vObj(map[string]value{
				"name":            vStr(s.Name),
				"virtual_address": vInt(int64(s.VirtualAddress)),
				"virtual_size":    vInt(int64(s.VirtualSize)),
				"raw_data_size":   vInt(int64(s.Size)),
				"raw_data_offset": vInt(int64(s.Offset)),
			}))
		}
		fields["sections"] = vArr(secs)
	}
	// Common machine constants so `pe.machine == pe.MACHINE_AMD64` resolves.
	fields["MACHINE_I386"] = vInt(0x014c)
	fields["MACHINE_AMD64"] = vInt(0x8664)
	fields["MACHINE_ARM"] = vInt(0x01c0)
	fields["MACHINE_ARM64"] = vInt(0xaa64)
	return vObj(fields)
}

func elfModule(data []byte) value {
	fields := map[string]value{}
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		fields["type"] = vInt(int64(f.Type))
		fields["machine"] = vInt(int64(f.Machine))
		fields["entry_point"] = vInt(int64(f.Entry))
		fields["number_of_sections"] = vInt(int64(len(f.Sections)))
		secs := make([]value, 0, len(f.Sections))
		for _, s := range f.Sections {
			secs = append(secs, vObj(map[string]value{
				"name":    vStr(s.Name),
				"size":    vInt(int64(s.Size)),
				"offset":  vInt(int64(s.Offset)),
				"address": vInt(int64(s.Addr)),
			}))
		}
		fields["sections"] = vArr(secs)
	}
	fields["ET_EXEC"] = vInt(2)
	fields["ET_DYN"] = vInt(3)
	return vObj(fields)
}
