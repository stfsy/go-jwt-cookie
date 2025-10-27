package jwtcookie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAlphanumeric_ValidInputs(t *testing.T) {
	t.Parallel()
	cases := []string{
		"abc",
		"ABC",
		"AbC123",
		"A_B",
		"a+b",
		"A+B_9",
		"Z9_+azAZ",
		"0_1+2A",
		"rsa-test",
	}
	for _, s := range cases {
		assert.Truef(t, isAlphanumeric(s), "expected %q to be valid", s)
	}
}

func TestIsAlphanumeric_InvalidInputs(t *testing.T) {
	t.Parallel()
	cases := []string{
		"space here",
		"slash/",
		"period.",
		"!bang",
		"@at",
		"#hash",
		"*star",
		"(paren)",
	}
	for _, s := range cases {
		assert.Falsef(t, isAlphanumeric(s), "expected %q to be invalid", s)
	}
}
