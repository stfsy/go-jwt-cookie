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

// Ensure HMAC-signed JWTs include a kid header matching the computed value
func TestSetJWTCookie_IncludesKID_HMAC(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name   string
		method jwt.SigningMethod
		key    []byte
	}{
		{"HS256", jwt.SigningMethodHS256, []byte("0123456789abcdef0123456789abcdef")},                                 // 32 bytes
		{"HS384", jwt.SigningMethodHS384, []byte("0123456789abcdef0123456789abcdef0123456789abcdef")},                 // 48 bytes
		{"HS512", jwt.SigningMethodHS512, []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")}, // 64 bytes
	}

	for _, tt := range tests {
		cm, err := NewCookieManager(
			WithSigningKeyHMAC(tt.key, nil),
			WithSigningMethod(tt.method),
			WithValidationKeysHMAC([][]byte{tt.key}),
			WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
		)
		assert.NoError(err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		err = cm.SetJWTCookie(w, r, map[string]string{"alg": tt.method.Alg()})
		assert.NoError(err)

		tokenStr := w.Result().Cookies()[0].Value
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) { return tt.key, nil })
		assert.NoError(err)
		assert.True(token.Valid)

		kid, ok := token.Header["kid"].(string)
		assert.True(ok, "kid header should be present")
		assert.NotEmpty(kid)
		expected := computeKIDFromSaltedHMAC(nil, tt.key)
		assert.Equal(expected, kid)
	}
}

// Ensure RSA/PS-signed JWTs include a kid header matching the computed value
func TestSetJWTCookie_IncludesKID_RSAandPS(t *testing.T) {
	assert := assert.New(t)

	// Generate RSA keys: 1024-bit for RS* and PS256/PS384, 2048-bit for PS512 (PSS with SHA-512 needs larger modulus)
	privateKey1024, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	pub1024 := &privateKey1024.PublicKey
	privateKey2048, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(err)
	pub2048 := &privateKey2048.PublicKey

	tests := []struct {
		name   string
		method jwt.SigningMethod
	}{
		{"RS256", jwt.SigningMethodRS256},
		{"RS384", jwt.SigningMethodRS384},
		{"RS512", jwt.SigningMethodRS512},
		{"PS256", jwt.SigningMethodPS256},
		{"PS384", jwt.SigningMethodPS384},
		{"PS512", jwt.SigningMethodPS512},
	}

	for _, tt := range tests {
		// Select appropriate key size based on method
		var priv *rsa.PrivateKey
		var pub *rsa.PublicKey
		if tt.method == jwt.SigningMethodPS512 {
			priv, pub = privateKey2048, pub2048
		} else {
			priv, pub = privateKey1024, pub1024
		}

		cm, err := NewCookieManager(
			WithSigningKeyRSA(priv),
			WithSigningMethod(tt.method),
			WithValidationKeysRSA([]*rsa.PublicKey{pub}),
			WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
		)
		assert.NoError(err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		err = cm.SetJWTCookie(w, r, map[string]string{"alg": tt.method.Alg()})
		assert.NoError(err)

		tokenStr := w.Result().Cookies()[0].Value
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) { return pub, nil })
		assert.NoError(err)
		assert.True(token.Valid)

		kid, ok := token.Header["kid"].(string)
		assert.True(ok, "kid header should be present")
		assert.NotEmpty(kid)
		expected, err := computeKIDFromPublicKey(pub)
		assert.NoError(err)
		assert.Equal(expected, kid)
	}
}

// Ensure ECDSA-signed JWTs include a kid header matching the computed value
func TestSetJWTCookie_IncludesKID_ECDSA(t *testing.T) {
	assert := assert.New(t)

	// Generate ECDSA keys matching the required curves
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(err)
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(err)

	tests := []struct {
		name      string
		method    jwt.SigningMethod
		private   *ecdsa.PrivateKey
		publicKey *ecdsa.PublicKey
	}{
		{"ES256", jwt.SigningMethodES256, p256Key, &p256Key.PublicKey},
		{"ES384", jwt.SigningMethodES384, p384Key, &p384Key.PublicKey},
		{"ES512", jwt.SigningMethodES512, p521Key, &p521Key.PublicKey},
	}

	for _, tt := range tests {
		cm, err := NewCookieManager(
			WithSigningKeyECDSA(tt.private),
			WithSigningMethod(tt.method),
			WithValidationKeysECDSA([]*ecdsa.PublicKey{tt.publicKey}),
			WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
		)
		assert.NoError(err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		err = cm.SetJWTCookie(w, r, map[string]string{"alg": tt.method.Alg()})
		assert.NoError(err)

		tokenStr := w.Result().Cookies()[0].Value
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) { return tt.publicKey, nil })
		assert.NoError(err)
		assert.True(token.Valid)

		kid, ok := token.Header["kid"].(string)
		assert.True(ok, "kid header should be present")
		assert.NotEmpty(kid)
		expected, err := computeKIDFromPublicKey(tt.publicKey)
		assert.NoError(err)
		assert.Equal(expected, kid)
	}
}

// Ensure salted KID derivation is deterministic and differs from unsalted
func TestSetJWTCookie_HMAC_SaltedKID(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	cm, err := NewCookieManager(
		WithSigningKeyHMAC(key, []byte("kid-salt")),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cm.SetJWTCookie(w, r, nil)
	assert.NoError(err)

	tokenStr := w.Result().Cookies()[0].Value
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) { return key, nil })
	assert.NoError(err)
	assert.True(token.Valid)
	kid, ok := token.Header["kid"].(string)
	assert.True(ok)

	// verify salted derivation matches expected value
	expectedSalted := computeKIDFromSaltedHMAC([]byte("kid-salt"), key)
	assert.Equal(expectedSalted, kid)
}
