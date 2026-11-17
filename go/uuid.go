package keelie

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // UUIDv5 is defined on SHA-1 (RFC 9562); it is a name, not a signature.
	"encoding/hex"
	"strings"
)

// parseUUID reads a UUID as Python's uuid.UUID(str) does, so that the SDKs
// accept and refuse the same values. It gives the canonical form, lowercase
// with hyphens, and false if value is not a UUID.
func parseUUID(value string) (string, bool) {
	// Python's order: drop "urn:" and "uuid:", the braces, then every hyphen.
	h := strings.ReplaceAll(value, "urn:", "")
	h = strings.ReplaceAll(h, "uuid:", "")
	h = strings.Trim(h, "{}")
	h = strings.ReplaceAll(h, "-", "")
	if len(h) != 32 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return "", false
		}
	}
	return format(strings.ToLower(h)), true
}

func format(h string) string {
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// uuid5 is the name-based UUID of RFC 9562, version 5 (SHA-1), as Python's
// uuid.uuid5 makes it. namespace must be a canonical UUID.
func uuid5(namespace, name string) string {
	ns, err := hex.DecodeString(strings.ReplaceAll(namespace, "-", ""))
	if err != nil || len(ns) != 16 {
		panic("keelie: the namespace is not a UUID")
	}
	digest := sha1.New() //nolint:gosec // see the import
	digest.Write(ns)
	digest.Write([]byte(name))
	sum := digest.Sum(nil)[:16]
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	return format(hex.EncodeToString(sum))
}

// uuid4 is a random UUID.
func uuid4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keelie: no randomness: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return format(hex.EncodeToString(b[:]))
}
