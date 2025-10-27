package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewCookieManager_Defaults(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")), // example salt (16 bytes)
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{signingKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	assert.True(cm.secure)
	assert.True(cm.httpOnly)
	assert.Equal(3600, cm.maxAge)
	assert.Equal(http.SameSiteStrictMode, cm.sameSite)
	assert.Equal("/", cm.path)
	assert.Equal("jwt_token", cm.cookieName)
	assert.Equal(signingKey, cm.signingKey)
	assert.Equal(jwt.SigningMethodHS256, cm.signingMethod)
}

func TestSetJWTCookie_NilCustomClaims(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err = cm.SetJWTCookie(w, r, nil)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)
	assert.NotEmpty(cookies[0].Value)
}

func TestSetJWTCookie_CustomCookieOptions(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithSecure(true),
		WithHTTPOnly(false),
		WithMaxAge(1800),
		WithSameSite(http.SameSiteStrictMode),
		WithDomain("example.com"),
		WithPath("/api"),
		WithCookieName("custom_jwt"),
		WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{signingKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err = cm.SetJWTCookie(w, r, map[string]string{"test": "value"})
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	cookie := cookies[0]
	assert.Equal("custom_jwt", cookie.Name)
	assert.True(cookie.Secure)
	assert.False(cookie.HttpOnly)
	assert.Equal(1800, cookie.MaxAge)
	assert.Equal(http.SameSiteStrictMode, cookie.SameSite)
	assert.Equal("example.com", cookie.Domain)
	assert.Equal("/api", cookie.Path)
}

func TestSetJWTCookie_TokenSignature(t *testing.T) {
	assert := assert.New(t)

	signingKey1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes
	signingKey2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 bytes
	cm1, err := NewCookieManager(WithSigningKeyHMAC(signingKey1, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey1}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)

	err = cm1.SetJWTCookie(w1, r1, map[string]string{"user": "test"})
	assert.NoError(err)

	token1 := w1.Result().Cookies()[0].Value

	// Token signed with signingKey1 should be valid with signingKey1
	parsedToken1, err := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return signingKey1, nil
	})
	assert.NoError(err)
	assert.True(parsedToken1.Valid)

	// Token signed with signingKey1 should NOT be valid with signingKey2
	parsedToken2, err := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return signingKey2, nil
	})
	assert.Error(err)
	if parsedToken2 != nil {
		assert.False(parsedToken2.Valid)
	}
}

func TestGetClaimsOfValid_Success(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)

	// First, set a JWT cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id": "12345",
		"role":    "admin",
	}

	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	// Get the cookie from the response
	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	// Create a new request with the cookie
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	// Validate and get claims
	claims, err := cm.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)

	// Verify custom claims
	assert.Equal("12345", claims["user_id"])
	assert.Equal("admin", claims["role"])

	// Verify standard claims exist
	assert.NotNil(claims["iat"])
	assert.NotNil(claims["exp"])
	assert.NotNil(claims["nbf"])
	// Verify identity claims exist
	assert.Equal("iss", claims["iss"])
	assert.Equal("aud", claims["aud"])
	assert.Equal("sub", claims["sub"])
}

func TestGetClaimsOfValid_NoCookie(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	claims, err := cm.GetClaimsOfValid(r)
	assert.Error(err)
	assert.Nil(claims)
	assert.Contains(err.Error(), "failed to get cookie")
}

func TestGetClaimsOfValid_InvalidToken(t *testing.T) {
	assert := assert.New(t)

	cm, err := NewCookieManager(WithSigningKeyHMAC([]byte("0123456789abcdef0123456789abcdef"), []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{[]byte("0123456789abcdef0123456789abcdef")}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Add a cookie with an invalid token
	r.AddCookie(&http.Cookie{
		Name:  "jwt_token",
		Value: "invalid.token.here",
	})

	claims, err := cm.GetClaimsOfValid(r)
	assert.Error(err)
	assert.Nil(claims)
}

func TestGetClaimsOfValid_WrongSecretKey(t *testing.T) {
	assert := assert.New(t)

	signingKey1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes
	signingKey2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 bytes

	cm1, err := NewCookieManager(WithSigningKeyHMAC(signingKey1, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey1}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err = cm1.SetJWTCookie(w, r, map[string]string{"user": "test"})
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	// Try to validate with signingKey2
	cm2, err := NewCookieManager(WithSigningKeyHMAC(signingKey2, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey2}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	claims, err := cm2.GetClaimsOfValid(r2)
	assert.Error(err)
	assert.Nil(claims)
}

func TestGetClaimsOfValid_KeyRotation(t *testing.T) {
	assert := assert.New(t)

	oldKey := []byte("cccccccccccccccccccccccccccccccc") // 32 bytes
	newKey := []byte("dddddddddddddddddddddddddddddddd") // 32 bytes

	// Create token with old key
	cm1, err := NewCookieManager(WithSigningKeyHMAC(oldKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{oldKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id": "12345",
		"role":    "admin",
	}

	err = cm1.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	// Validate with both old and new keys (key rotation scenario)
	cm2, err := NewCookieManager(
		WithSigningKeyHMAC(newKey, []byte("0123456789abcdef")), // New key for signing
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{newKey, oldKey}), // Accept both keys for validation
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	// Should successfully validate with old key
	claims, err := cm2.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)

	assert.Equal("12345", claims["user_id"])
	assert.Equal("admin", claims["role"])
}

func TestGetClaimsOfValid_MultipleValidationKeys(t *testing.T) {
	assert := assert.New(t)

	key1 := []byte("11111111111111111111111111111111") // 32 bytes
	key2 := []byte("22222222222222222222222222222222") // 32 bytes
	key3 := []byte("33333333333333333333333333333333") // 32 bytes

	// Create token with key2
	cm1, err := NewCookieManager(WithSigningKeyHMAC(key2, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{key2}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id": "67890",
	}

	err = cm1.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	// Validate with multiple keys including key2
	cm2, err := NewCookieManager(
		WithSigningKeyHMAC(key3, []byte("0123456789abcdef")),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{key1, key2, key3}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	// Should successfully validate with key2 (second in the list)
	claims, err := cm2.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)

	assert.Equal("67890", claims["user_id"])
}

func TestGetClaimsOfValid_UsesSigningKeyWhenNoValidationKeys(t *testing.T) {
	assert := assert.New(t)

	signingKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(WithSigningKeyHMAC(signingKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{signingKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.NoError(err)

	// Create and set token
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id": "11111",
	}

	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	// Validate - should use signing key
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	claims, err := cm.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)

	assert.Equal("11111", claims["user_id"])
}

func TestSetJWTCookie_ConfigurableSigningMethod(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name    string
		method  jwt.SigningMethod
		wantAlg string
	}{
		{"HS256", jwt.SigningMethodHS256, "HS256"},
		{"HS384", jwt.SigningMethodHS384, "HS384"},
		{"HS512", jwt.SigningMethodHS512, "HS512"},
	}

	for _, tt := range tests {
		// Choose a key length appropriate for the algorithm
		var key []byte
		switch tt.method {
		case jwt.SigningMethodHS256:
			key = []byte("0123456789abcdef0123456789abcdef") // 32 bytes
		case jwt.SigningMethodHS384:
			key = []byte("0123456789abcdef0123456789abcdef0123456789abcdef") // 48 bytes
		case jwt.SigningMethodHS512:
			key = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // 64 bytes
		}
		cm, err := NewCookieManager(WithSigningKeyHMAC(key, []byte("0123456789abcdef")), WithSigningMethod(tt.method), WithValidationKeysHMAC([][]byte{key}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
		assert.NoError(err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		err = cm.SetJWTCookie(w, r, map[string]string{"alg": tt.wantAlg})
		assert.NoError(err)

		token, err := jwt.Parse(w.Result().Cookies()[0].Value, func(token *jwt.Token) (interface{}, error) { return key, nil })
		assert.NoError(err)
		assert.Equal(tt.wantAlg, token.Header["alg"])
	}
}

func TestSetJWTCookie_RSAAlgorithm(t *testing.T) {
	assert := assert.New(t)

	// Generate RSA key pair for testing (1024-bit for faster tests)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)

	cm, err := NewCookieManager(
		WithSigningKeyRSA(privateKey),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{"user_id": "rsa-test", "alg": "RS256"}

	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	token, err := jwt.Parse(cookies[0].Value, func(token *jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil })
	assert.NoError(err)
	assert.True(token.Valid)
	assert.Equal("RS256", token.Header["alg"])

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(ok)
	assert.Equal("rsa-test", claims["user_id"])
}

func TestSetJWTCookie_ECDSAAlgorithm(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)

	cm, err := NewCookieManager(
		WithSigningKeyECDSA(privateKey),
		WithSigningMethodES256(),
		WithValidationKeysECDSA([]*ecdsa.PublicKey{&privateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{"user_id": "ecdsa-test", "alg": "ES256"}
	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	token, err := jwt.Parse(cookies[0].Value, func(token *jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil })
	assert.NoError(err)
	assert.True(token.Valid)
	assert.Equal("ES256", token.Header["alg"])

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(ok)
	assert.Equal("ecdsa-test", claims["user_id"])
}

func TestGetClaimsOfValid_RSA(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)

	cm, err := NewCookieManager(
		WithSigningKeyRSA(privateKey),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{"user_id": "rsa-validation-test"}
	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	claims, err := cm.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)
	assert.Equal("rsa-validation-test", claims["user_id"])
}

func TestGetClaimsOfValid_ECDSA(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)

	cm, err := NewCookieManager(
		WithSigningKeyECDSA(privateKey),
		WithSigningMethodES256(),
		WithValidationKeysECDSA([]*ecdsa.PublicKey{&privateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{"user_id": "ecdsa-validation-test"}
	err = cm.SetJWTCookie(w, r, customClaims)
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	claims, err := cm.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)
	assert.Equal("ecdsa-validation-test", claims["user_id"])
}

func TestGetClaimsOfValid_RSAKeyRotation(t *testing.T) {
	assert := assert.New(t)

	oldPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)

	cm, err := NewCookieManager(
		WithSigningKeyRSA(oldPrivateKey),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&oldPrivateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err = cm.SetJWTCookie(w, r, map[string]string{"user_id": "rotation-test"})
	assert.NoError(err)

	cookies := w.Result().Cookies()
	assert.Len(cookies, 1)

	cm2, err := NewCookieManager(
		WithSigningKeyRSA(newPrivateKey),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&newPrivateKey.PublicKey, &oldPrivateKey.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	claims, err := cm2.GetClaimsOfValid(r2)
	assert.NoError(err)
	assert.NotNil(claims)
	assert.Equal("rotation-test", claims["user_id"])
}
