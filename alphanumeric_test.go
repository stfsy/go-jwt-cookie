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
		"0_1+2A#",
		"rsa-test",
	}
	for _, s := range cases {
		assert.Truef(t, isAlphanumericUtf8(s), "expected %q to be valid", s)
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
		"*star",
		"(paren)",
	}
	for _, s := range cases {
		assert.Falsef(t, isAlphanumericUtf8(s), "expected %q to be invalid", s)
	}
}

func TestIsAlphanumeric_InvalidUTF8Inputs(t *testing.T) {
	t.Parallel()
	cases := []string{
		string([]byte{0xff}),
		string([]byte{0xc3, 0x28}),
		string([]byte{'A', 0xff, 'Z'}),
	}

	for _, s := range cases {
		assert.False(t, isAlphanumericUtf8(s), "expected invalid UTF-8 string to be rejected")
	}
}
