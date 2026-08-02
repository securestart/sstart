package provider

import (
	"fmt"
	"strconv"
	"strings"
)

// ResolvePointer resolves an RFC 6901 JSON pointer against a decoded JSON
// document.
//
// A pointer is used rather than a dotted path because real key names contain
// dots, pipes and colons; RFC 6901 already defines how to escape the two
// characters that are special to it.
func ResolvePointer(document interface{}, pointer string) (interface{}, error) {
	if pointer == "" {
		return document, nil
	}

	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer %q must start with '/'", pointer)
	}

	current := document
	// A leading "/" produces an empty first element, which is not a token.
	for _, token := range strings.Split(pointer, "/")[1:] {
		// ~1 must be decoded before ~0, otherwise "~01" would become "/".
		token = strings.ReplaceAll(token, "~1", "/")
		token = strings.ReplaceAll(token, "~0", "~")

		switch container := current.(type) {
		case map[string]interface{}:
			value, exists := container[token]
			if !exists {
				return nil, fmt.Errorf("JSON pointer %q: no key %q", pointer, token)
			}
			current = value

		case []interface{}:
			index, err := strconv.Atoi(token)
			if err != nil {
				return nil, fmt.Errorf("JSON pointer %q: %q is not an array index", pointer, token)
			}
			if index < 0 || index >= len(container) {
				return nil, fmt.Errorf("JSON pointer %q: index %d is out of range, length is %d", pointer, index, len(container))
			}
			current = container[index]

		default:
			return nil, fmt.Errorf("JSON pointer %q: cannot descend into %T at %q", pointer, current, token)
		}
	}

	return current, nil
}
