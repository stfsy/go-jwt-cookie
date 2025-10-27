package jwtcookie

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '_' ||
			r == '+' ||
			r == '-') {
			return false
		}
	}
	return true
}
