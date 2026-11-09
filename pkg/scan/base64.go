package scan

// base64 modifier support. A string can appear base64-encoded at three byte
// alignments (base64 packs 3 bytes into 4 chars, so the pattern may begin at
// offset 0, 1, or 2 within a 3-byte group). For each alignment we prepend that
// many bytes, encode, and keep only the base64 characters whose 6 bits lie
// ENTIRELY within the pattern's bytes — the characters that match regardless of
// the surrounding data. This yields no false negatives; exact character-count
// parity with YARA is a differential-testing refinement.

const stdBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// base64Subs returns the (deduplicated) alignment sub-patterns for value under
// the given 64-character alphabet ("" → the standard alphabet).
func base64Subs(value []byte, alphabet string) [][]byte {
	if alphabet == "" {
		alphabet = stdBase64
	}
	if len(alphabet) != 64 {
		return nil
	}
	var out [][]byte
	for pad := 0; pad < 3; pad++ {
		if sub := base64Align(value, pad, alphabet); sub != nil {
			dup := false
			for _, e := range out {
				if string(e) == string(sub) {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, sub)
			}
		}
	}
	return out
}

// base64Align encodes `pad` zero bytes followed by value, then returns the
// substring of base64 characters fully determined by value's bytes.
func base64Align(value []byte, pad int, alphabet string) []byte {
	padded := make([]byte, pad+len(value))
	copy(padded[pad:], value)
	enc := b64raw(padded, alphabet)

	n := pad + len(value)
	// A char j spans bits [6j, 6j+6); it is fully within value's region
	// [8*pad, 8*n) iff 6j >= 8*pad and 6j+6 <= 8*n.
	lead := (8*pad + 5) / 6  // ceil(8*pad / 6)
	keptEnd := (8*n-6)/6 + 1 // last j with 6j+6 <= 8n, plus one
	if keptEnd > len(enc) {
		keptEnd = len(enc)
	}
	if lead >= keptEnd {
		return nil
	}
	return enc[lead:keptEnd]
}

// b64raw encodes b to base64 with the given alphabet and no `=` padding.
func b64raw(b []byte, alphabet string) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, 0, (len(b)*4+2)/3)
	i := 0
	for ; i+3 <= len(b); i += 3 {
		v := uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		out = append(out, alphabet[v>>18&0x3f], alphabet[v>>12&0x3f], alphabet[v>>6&0x3f], alphabet[v&0x3f])
	}
	switch len(b) - i {
	case 1:
		v := uint32(b[i]) << 16
		out = append(out, alphabet[v>>18&0x3f], alphabet[v>>12&0x3f])
	case 2:
		v := uint32(b[i])<<16 | uint32(b[i+1])<<8
		out = append(out, alphabet[v>>18&0x3f], alphabet[v>>12&0x3f], alphabet[v>>6&0x3f])
	}
	return out
}
