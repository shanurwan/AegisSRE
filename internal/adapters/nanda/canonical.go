// Package nanda publishes signed AgentFacts and resolves A2A peers through the
// Project NANDA Index. It is a discovery adapter: the delegation grant, mTLS
// and workload policy stay the authority boundary whether or not it is used.
package nanda

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Canonicalize serializes a decoded JSON value exactly as the NANDA Index's
// canonicalize() does (nanda-index-v2 server/src/services/signing.ts): object
// keys sorted recursively, no whitespace, arrays in order, strings and numbers
// formatted like ECMAScript JSON.stringify. Signatures are only portable
// between the TypeScript and Go implementations if these bytes match.
//
// Values must come from a json.Decoder with UseNumber, or be plain Go maps,
// slices, strings, bools, nil and json.Number.
func Canonicalize(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := canonicalize(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func canonicalize(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case json.Number:
		number, err := typed.Float64()
		if err != nil {
			return fmt.Errorf("canonicalize number %q: %w", typed, err)
		}
		formatted, err := ecmaNumber(number)
		if err != nil {
			return err
		}
		buffer.WriteString(formatted)
	case string:
		if !utf8.ValidString(typed) {
			return errors.New("canonicalize: string is not valid UTF-8")
		}
		writeECMAString(buffer, typed)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := canonicalize(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		// JavaScript sorts object keys by UTF-16 code units. They agree with
		// Go's byte order for every key below U+10000, which covers AgentFacts.
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if !utf8.ValidString(key) {
				return errors.New("canonicalize: object key is not valid UTF-8")
			}
			writeECMAString(buffer, key)
			buffer.WriteByte(':')
			if err := canonicalize(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", value)
	}
	return nil
}

// writeECMAString escapes like JSON.stringify: quote, backslash and control
// characters only. Unlike encoding/json it leaves <, >, & and U+2028 alone.
func writeECMAString(buffer *bytes.Buffer, value string) {
	const hex = "0123456789abcdef"
	buffer.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			if character < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(hex[character>>4])
				buffer.WriteByte(hex[character&0xf])
			} else {
				buffer.WriteRune(character)
			}
		}
	}
	buffer.WriteByte('"')
}

// ecmaNumber implements ECMAScript Number::toString for finite doubles.
func ecmaNumber(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", errors.New("canonicalize: non-finite numbers are not representable")
	}
	if value == 0 {
		return "0", nil
	}
	sign := ""
	if value < 0 {
		sign, value = "-", -value
	}
	// Shortest round-trip digits and decimal exponent, e.g. "1.2345e+06".
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, exponentText, _ := strings.Cut(scientific, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		return "", fmt.Errorf("canonicalize number: %w", err)
	}
	k, n := len(digits), exponent+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}
	exponentSign := "+"
	if n-1 < 0 {
		exponentSign = "-"
	}
	magnitude := strconv.Itoa(int(math.Abs(float64(n - 1))))
	if k == 1 {
		return sign + digits + "e" + exponentSign + magnitude, nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + exponentSign + magnitude, nil
}

// decodeGeneric decodes a JSON document into the value shape Canonicalize
// accepts, rejecting trailing data.
func decodeGeneric(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing data after JSON document")
	}
	return document, nil
}
