package jwtcookie

import "unicode/utf8"

//nolint:all
func isAlphanumericUtf8(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}

	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '_' ||
			r == '+' ||
			r == '#' ||
			r == '-') {
			return false
		}
	}
	return true
}
