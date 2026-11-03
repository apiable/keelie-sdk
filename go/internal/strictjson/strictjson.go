// Package strictjson reads JSON that two parsers read the same way.
//
// encoding/json keeps the last value of a key given twice, and another parser
// may keep the first. A guard that read one tool name while the MCP server read
// another would check the wrong scope. So a key given twice in one object is
// refused, as the Python SDK refuses it. Keys compare after their escapes are
// read: "a" and "\u0061" are the same key.
//
// Nesting deeper than MaxDepth is refused, as Python's parser refuses it at its
// recursion limit. A body that is not UTF-8 is refused: encoding/json would
// read it, putting U+FFFD where a byte is not UTF-8.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting of objects and arrays that is read.
const MaxDepth = 1000

var (
	// ErrSyntax is a body that is not UTF-8 JSON.
	ErrSyntax = errors.New("strictjson: not UTF-8 JSON")
	// ErrDuplicateKey is an object with a key given twice.
	ErrDuplicateKey = errors.New("strictjson: a key given twice")
	// ErrTooDeep is a body nested deeper than MaxDepth.
	ErrTooDeep = errors.New("strictjson: nested too deeply")
)

// Parse reads data as one JSON value. An object is a map[string]any, an array
// a []any, a number a json.Number, and null is nil.
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, ErrSyntax
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrSyntax
	}
	value, err := parse(dec, tok, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrSyntax
	}
	return value, nil
}

func parse(dec *json.Decoder, tok json.Token, depth int) (any, error) {
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	depth++
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, ErrSyntax
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, ErrSyntax
			}
			if _, seen := object[key]; seen {
				return nil, ErrDuplicateKey
			}
			valueTok, err := dec.Token()
			if err != nil {
				return nil, ErrSyntax
			}
			value, err := parse(dec, valueTok, depth)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return nil, ErrSyntax
		}
		return object, nil
	case '[':
		array := []any{}
		for dec.More() {
			valueTok, err := dec.Token()
			if err != nil {
				return nil, ErrSyntax
			}
			value, err := parse(dec, valueTok, depth)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return nil, ErrSyntax
		}
		return array, nil
	}
	return nil, ErrSyntax
}
