package jwtcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzSetJWTCookie fuzzes the SetJWTCookie function with random inputs
func FuzzSetJWTCookie(f *testing.F) {
	// Seed corpus with some basic examples
	f.Add([]byte("signing-key"), "user_id", "12345", "role", "admin")
	f.Add([]byte("another-key"), "email", "test@example.com", "name", "Test User")
	f.Add([]byte("short"), "a", "b", "c", "d")
	f.Add([]byte(""), "key", "value", "", "")

	f.Fuzz(func(t *testing.T, signingKey []byte, key1, val1, key2, val2 string) {
		// Skip if signing key is empty as it would cause issues
		if len(signingKey) == 0 {
			return
		}

		cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}))
		if err != nil {
			t.Skip("failed to create cookie manager")
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		// Build claims map
		claims := make(map[string]string)
		if key1 != "" {
			claims[key1] = val1
		}
		if key2 != "" {
			claims[key2] = val2
		}

		// Test SetJWTCookie - should not panic
		err = cm.SetJWTCookie(w, r, claims)

		// We expect no error in normal operation
		if err != nil {
			t.Skip("Error occurred, but not a crash")
		}

		// Verify a cookie was set
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Errorf("Expected 1 cookie, got %d", len(cookies))
		}
	})
}

// FuzzGetClaimsOfValid fuzzes the GetClaimsOfValid function with random inputs
func FuzzGetClaimsOfValid(f *testing.F) {
	// Seed corpus with some basic examples
	f.Add([]byte("signing-key"), "jwt_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	f.Add([]byte("another-key"), "custom_token", "invalid.token.value")
	f.Add([]byte("test"), "jwt_token", "")
	f.Add([]byte(""), "jwt_token", "some-value")

	f.Fuzz(func(t *testing.T, signingKey []byte, cookieName, tokenValue string) {
		// Skip if signing key is empty
		if len(signingKey) == 0 {
			return
		}

		// Skip if cookie name is empty (would use default)
		if cookieName == "" {
			cookieName = "jwt_token"
		}

		cm, err := NewCookieManager(
			WithSigningKeyHMAC(signingKey),
			WithSigningMethodHS256(),
			WithValidationKeysHMAC([][]byte{signingKey}),
			WithCookieName(cookieName),
		)
		if err != nil {
			t.Skip("failed to create cookie manager")
		}

		r := httptest.NewRequest(http.MethodGet, "/", nil)

		// Add cookie if token value is not empty
		if tokenValue != "" {
			r.AddCookie(&http.Cookie{
				Name:  cookieName,
				Value: tokenValue,
			})
		}

		// Test GetClaimsOfValid - should not panic
		claims, err := cm.GetClaimsOfValid(r)

		// Most random inputs will fail validation, which is expected
		// We're mainly testing that the function doesn't panic
		if err == nil && claims == nil {
			t.Error("No error but claims is nil")
		}
	})
}

// FuzzRoundTrip fuzzes a round trip of setting and getting JWT cookies
func FuzzRoundTrip(f *testing.F) {
	// Seed corpus
	f.Add([]byte("signing-key"), "user_id", "12345")
	f.Add([]byte("another-secret"), "email", "test@example.com")
	f.Add([]byte("x"), "a", "b")

	f.Fuzz(func(t *testing.T, signingKey []byte, claimKey, claimValue string) {
		// Skip if signing key is empty
		if len(signingKey) == 0 {
			return
		}

		cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}))
		if err != nil {
			t.Errorf("Failed to create cookie manager: %v", err)
			return
		}

		// Set cookie
		w := httptest.NewRecorder()
		r1 := httptest.NewRequest(http.MethodGet, "/", nil)

		claims := make(map[string]string)
		if claimKey != "" {
			claims[claimKey] = claimValue
		}

		err = cm.SetJWTCookie(w, r1, claims)
		if err != nil {
			t.Skip("Error setting cookie")
		}

		// Get cookie
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Skip("No cookie set")
		}

		// Validate cookie
		r2 := httptest.NewRequest(http.MethodGet, "/", nil)
		r2.AddCookie(cookies[0])

		retrievedClaims, err := cm.GetClaimsOfValid(r2)
		if err != nil {
			t.Errorf("Failed to validate token that was just created: %v", err)
		}

		// Verify the custom claim if it was set
		if claimKey != "" {
			if val, ok := retrievedClaims[claimKey]; ok {
				if val != claimValue {
					t.Errorf("Claim value mismatch: expected %s, got %v", claimValue, val)
				}
			} else {
				t.Errorf("Claim %s not found in retrieved claims", claimKey)
			}
		}
	})
}
