// Package pyjson writes JSON as Python's json.dumps writes it with its defaults
// and compact separators, so that the Go SDK sends the bytes the Python SDK
// sends: every character outside printable ASCII is escaped as \uXXXX.
package pyjson

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

const hex = "0123456789abcdef"

// String writes s as a quoted JSON string. A byte that is not UTF-8 is written
// as U+FFFD; the SDK refuses such a value before it gets here.
func String(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			b.WriteByte(byte(r))
		case r > 0xffff:
			r -= 0x10000
			unicode(b, 0xd800+(r>>10))
			unicode(b, 0xdc00+(r&0x3ff))
		default:
			unicode(b, r)
		}
	}
	b.WriteByte('"')
}

func unicode(b *bytes.Buffer, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hex[r>>12&0xf])
	b.WriteByte(hex[r>>8&0xf])
	b.WriteByte(hex[r>>4&0xf])
	b.WriteByte(hex[r&0xf])
}

// Object writes a flat object of string members, in the order given.
func Object(b *bytes.Buffer, pairs ...string) {
	b.WriteByte('{')
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		String(b, pairs[i])
		b.WriteByte(':')
		String(b, pairs[i+1])
	}
	b.WriteByte('}')
}

// Int writes n.
func Int(b *bytes.Buffer, n int) {
	b.WriteString(strconv.Itoa(n))
}
