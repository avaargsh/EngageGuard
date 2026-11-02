package action

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxCanonicalJSONBytes = 128 * 1024
	maxJSONDepth          = 64
)

// canonicalJSONObject applies RFC 8785 JCS to a UTF-8 JSON object. Duplicate
// keys, invalid surrogate escapes, excessive nesting and non-finite numbers are
// rejected rather than silently normalized into a different action.
func canonicalJSONObject(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxCanonicalJSONBytes || !utf8.Valid(raw) {
		return nil, errors.New("JSON object is empty, oversized or invalid UTF-8")
	}
	if err := validateUnicodeEscapes(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("JSON value must be an object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON data")
	}
	return appendCanonicalValue(nil, value)
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds maximum depth %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid JSON object key")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON object key %q", key)
			}
			value, err := readJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated JSON object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := readJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func appendCanonicalValue(dst []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if typed {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case string:
		return appendJSONString(dst, typed), nil
	case json.Number:
		number, err := canonicalizeNumber(string(typed))
		if err != nil {
			return nil, err
		}
		return append(dst, number...), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range typed {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			dst, err = appendCanonicalValue(dst, item)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		dst = append(dst, '{')
		for i, key := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, key)
			dst = append(dst, ':')
			var err error
			dst, err = appendCanonicalValue(dst, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("unsupported JSON value type %T", value)
	}
}

func utf16Less(left, right string) bool {
	l := utf16.Encode([]rune(left))
	r := utf16.Encode([]rune(right))
	limit := len(l)
	if len(r) < limit {
		limit = len(r)
	}
	for i := 0; i < limit; i++ {
		if l[i] != r[i] {
			return l[i] < r[i]
		}
	}
	return len(l) < len(r)
}

func canonicalizeNumber(value string) (string, error) {
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		// ECMAScript/JCS rounds underflow to the nearest IEEE-754 value (which
		// may be zero); overflow to infinity is not a valid JCS number.
		if numberErr, ok := err.(*strconv.NumError); !ok || numberErr.Err != strconv.ErrRange || math.IsInf(number, 0) {
			return "", fmt.Errorf("JSON number %q is outside the IEEE-754 range", value)
		}
	}
	if math.IsInf(number, 0) || math.IsNaN(number) {
		return "", fmt.Errorf("JSON number %q is outside the IEEE-754 range", value)
	}
	if number == 0 { // JCS serializes both positive and negative zero as 0.
		return "0", nil
	}

	exponential := strconv.FormatFloat(number, 'e', -1, 64)
	parts := strings.SplitN(exponential, "e", 2)
	mantissa := parts[0]
	exponent, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid canonical exponent for %q", value)
	}
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign = "-"
		mantissa = strings.TrimPrefix(mantissa, "-")
	}

	if exponent >= -6 && exponent < 21 {
		point := strings.IndexByte(mantissa, '.')
		if point < 0 {
			point = len(mantissa)
		}
		digits := strings.ReplaceAll(mantissa, ".", "")
		decimalPosition := point + exponent
		switch {
		case decimalPosition <= 0:
			return sign + "0." + strings.Repeat("0", -decimalPosition) + digits, nil
		case decimalPosition >= len(digits):
			return sign + digits + strings.Repeat("0", decimalPosition-len(digits)), nil
		default:
			return sign + digits[:decimalPosition] + "." + digits[decimalPosition:], nil
		}
	}

	exponentSign := ""
	if exponent >= 0 {
		exponentSign = "+"
	}
	return sign + mantissa + "e" + exponentSign + strconv.Itoa(exponent), nil
}

// validateUnicodeEscapes rejects unpaired UTF-16 surrogate escapes. encoding/json
// otherwise replaces these with U+FFFD, which would silently change hash input.
func validateUnicodeEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw); i++ {
			switch raw[i] {
			case '"':
				goto nextString
			case '\\':
				i++
				if i >= len(raw) {
					return errors.New("unterminated JSON escape")
				}
				if raw[i] != 'u' {
					continue
				}
				unit, ok := parseHexCodeUnit(raw, i+1)
				if !ok {
					return errors.New("invalid Unicode escape")
				}
				i += 4
				if unit >= 0xdc00 && unit <= 0xdfff {
					return errors.New("unpaired low surrogate in JSON string")
				}
				if unit >= 0xd800 && unit <= 0xdbff {
					if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
						return errors.New("unpaired high surrogate in JSON string")
					}
					low, ok := parseHexCodeUnit(raw, i+3)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return errors.New("unpaired high surrogate in JSON string")
					}
					i += 6
				}
			}
		}
		return errors.New("unterminated JSON string")
	nextString:
	}
	return nil
}

func parseHexCodeUnit(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[start:start+4]), 16, 16)
	return uint16(value), err == nil
}
