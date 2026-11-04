package sdk

import (
	"unicode"
	"unicode/utf8"
)

// IsTextContent reports whether content is valid UTF-8 without binary control characters.
func IsTextContent(content []byte) bool {
	if !utf8.Valid(content) {
		return false
	}
	for _, character := range string(content) {
		if unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}
