package jwtcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCookiePrefix_Host(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Valid __Host- configuration
	cm, err := NewCookieManager(
		WithCookieName("__Host-jwt"),
		WithHTTPOnly(false), // should remain as-is (spec doesn't require HttpOnly)
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.NoError(err)

	// Prefix enforcement applied at construction
	assert.True(cm.secure)
	assert.Equal("/", cm.path)
	assert.Equal("", cm.domain)

	// Verify cookie emitted reflects enforced attributes
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cm.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)
	c := cookies[0]
	assert.Equal("__Host-jwt", c.Name)
	assert.True(c.Secure)
	assert.Equal("/", c.Path)
	assert.Equal("", c.Domain)
}

func TestCookiePrefix_Host_FailFastConflicts(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Conflicting WithDomain
	_, err := NewCookieManager(
		WithCookieName("__Host-jwt"),
		WithDomain("example.com"),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Domain")

	// Conflicting WithSecure(false)
	_, err = NewCookieManager(
		WithCookieName("__Host-jwt"),
		WithSecure(false),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Secure")

	// Conflicting WithPath("/subpath")
	_, err = NewCookieManager(
		WithCookieName("__Host-jwt"),
		WithPath("/subpath"),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Path")
}

func TestCookiePrefix_Secure(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithCookieName("__Secure-jwt"),
		WithDomain("example.com"), // allowed for __Secure-
		WithPath("/api"),          // allowed for __Secure-
		WithSecure(false),         // should be forced to true
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.NoError(err)

	// Prefix enforcement applied at construction
	assert.True(cm.secure)
	assert.Equal("/api", cm.path)
	assert.Equal("example.com", cm.domain)

	// Verify cookie emitted reflects enforced attributes
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cm.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)
	c := cookies[0]
	assert.Equal("__Secure-jwt", c.Name)
	assert.True(c.Secure)
	assert.Equal("/api", c.Path)
	assert.Equal("example.com", c.Domain)
}

func TestCookiePrefix_HostHttp(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithCookieName("__Host-Http-session"),
		WithHTTPOnly(false), // should be forced to true
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.NoError(err)

	assert.True(cm.httpOnly)
	assert.True(cm.secure)
	assert.Equal("/", cm.path)
	assert.Equal("", cm.domain)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cm.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)

	c := w.Result().Cookies()[0]
	assert.Equal("__Host-Http-session", c.Name)
	assert.True(c.HttpOnly)
	assert.True(c.Secure)
	assert.Equal("/", c.Path)
	assert.Equal("", c.Domain)
}

func TestCookiePrefix_HostHttp_FailFastConflicts(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Conflicting WithDomain
	_, err := NewCookieManager(
		WithCookieName("__Host-Http-session"),
		WithDomain("example.com"),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Domain")

	// Conflicting WithSecure(false)
	_, err = NewCookieManager(
		WithCookieName("__Host-Http-session"),
		WithSecure(false),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Secure")

	// Conflicting WithPath("/sub")
	_, err = NewCookieManager(
		WithCookieName("__Host-Http-session"),
		WithPath("/sub"),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.Error(err)
	assert.Contains(err.Error(), "Path")
}

func TestCookiePrefix_Http(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithCookieName("__Http-session"),
		WithHTTPOnly(false), // should be forced to true
		WithSecure(false),   // should be forced to true by __Http-
		WithDomain("example.com"),
		WithPath("/api"),
		WithSigningKeyHMAC(key, []byte("0123456789abcdef")),
		WithSigningMethod(jwt.SigningMethodHS256),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"),
	)
	assert.NoError(err)

	assert.True(cm.httpOnly)
	assert.True(cm.secure)
	assert.Equal("/api", cm.path)
	assert.Equal("example.com", cm.domain)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cm.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)

	c := w.Result().Cookies()[0]
	assert.Equal("__Http-session", c.Name)
	assert.True(c.HttpOnly)
	assert.True(c.Secure)
	assert.Equal("/api", c.Path)
	assert.Equal("example.com", c.Domain)
}
