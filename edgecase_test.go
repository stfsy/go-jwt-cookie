package jwtcookie

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCookieManager_ValidationErrors(t *testing.T) {
	t.Skip("replaced by dedicated tests")
}

func TestNewCookieManager_MissingSigningMethod(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey, nil), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_MissingSigningKey(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_MissingValidationKeys(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey, nil), WithSigningMethodHS256(), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_HMACWrongKeyType(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyRSA(&rsa.PrivateKey{}), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_RSAWrongSigningKeyType(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey, nil), WithSigningMethodRS256(), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_ECDSAValidationKeysWrongType(t *testing.T) {
	assert := assert.New(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := NewCookieManager(WithSigningKeyECDSA(priv), WithSigningMethodES256(), WithValidationKeysRSA([]*rsa.PublicKey{}), WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
}

func TestNewCookieManager_RequiresIssAudSub(t *testing.T) {
	assert := assert.New(t)
	key := bytes.Repeat([]byte{'x'}, 32)

	// Missing iss
	_, err := NewCookieManager(WithSigningKeyHMAC(key, nil), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{key}), WithAudience("aud"), WithSubject("sub"))
	assert.Error(err)
	// Missing aud
	_, err = NewCookieManager(WithSigningKeyHMAC(key, nil), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{key}), WithIssuer("iss"), WithSubject("sub"))
	assert.Error(err)
	// Missing sub
	_, err = NewCookieManager(WithSigningKeyHMAC(key, nil), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{key}), WithIssuer("iss"), WithAudience("aud"))
	assert.Error(err)
}

func TestNewCookieManager_HMACKeyMinLengths(t *testing.T) {
	assert := assert.New(t)

	// HS256 requires >= 32 bytes
	tooShort256 := bytes.Repeat([]byte{'a'}, 31)
	ok256 := bytes.Repeat([]byte{'a'}, 32)
	_, err := NewCookieManager(
		WithSigningKeyHMAC(tooShort256, nil),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{ok256}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.Error(err)

	_, err = NewCookieManager(
		WithSigningKeyHMAC(ok256, nil),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{ok256}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	// HS384 requires >= 48 bytes
	tooShort384 := bytes.Repeat([]byte{'b'}, 47)
	ok384 := bytes.Repeat([]byte{'b'}, 48)
	_, err = NewCookieManager(
		WithSigningKeyHMAC(ok384, nil),
		WithSigningMethodHS384(),
		WithValidationKeysHMAC([][]byte{tooShort384}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.Error(err)

	_, err = NewCookieManager(
		WithSigningKeyHMAC(ok384, nil),
		WithSigningMethodHS384(),
		WithValidationKeysHMAC([][]byte{ok384}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	// HS512 requires >= 64 bytes
	tooShort512 := bytes.Repeat([]byte{'c'}, 63)
	ok512 := bytes.Repeat([]byte{'c'}, 64)
	_, err = NewCookieManager(
		WithSigningKeyHMAC(tooShort512, nil),
		WithSigningMethodHS512(),
		WithValidationKeysHMAC([][]byte{ok512}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.Error(err)

	_, err = NewCookieManager(
		WithSigningKeyHMAC(ok512, nil),
		WithSigningMethodHS512(),
		WithValidationKeysHMAC([][]byte{ok512}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)
}

func TestGetClaimsOfValid_ExactAlgMatchEnforced(t *testing.T) {
	assert := assert.New(t)

	// Create an RS256-signed token
	privRS, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	cmRS, err := NewCookieManager(
		WithSigningKeyRSA(privRS),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privRS.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cmRS.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)
	cookie := w.Result().Cookies()[0]

	// Create a manager expecting PS256 (RSA-PSS). Must reject RS256 token now.
	privPS, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	cmPS, err := NewCookieManager(
		WithSigningKeyRSA(privPS),
		WithSigningMethodPS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privPS.PublicKey, &privRS.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	claims, err := cmPS.GetClaimsOfValid(r2)
	assert.Error(err)
	assert.Nil(claims)
}

func TestGetClaimsOfValid_ExactAlgMatchEnforced_Reverse(t *testing.T) {
	assert := assert.New(t)

	// Create a PS256-signed token
	privPS, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	cmPS, err := NewCookieManager(
		WithSigningKeyRSA(privPS),
		WithSigningMethodPS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privPS.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = cmPS.SetJWTCookie(w, r, map[string]string{"k": "v"})
	assert.NoError(err)
	cookie := w.Result().Cookies()[0]

	// Manager expecting RS256 must reject the PS256 token
	privRS, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	cmRS, err := NewCookieManager(
		WithSigningKeyRSA(privRS),
		WithSigningMethodRS256(),
		WithValidationKeysRSA([]*rsa.PublicKey{&privRS.PublicKey, &privPS.PublicKey}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	claims, err := cmRS.GetClaimsOfValid(r2)
	assert.Error(err)
	assert.Nil(claims)
}

func TestSetJWTCookie_ReservedClaimsCannotOverride(t *testing.T) {
	assert := assert.New(t)

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(
		WithSigningKeyHMAC(key, nil),
		WithSigningMethodHS256(),
		WithValidationKeysHMAC([][]byte{key}),
		WithIssuer("iss"), WithAudience("aud"), WithSubject("sub"),
	)
	assert.NoError(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Provide bogus reserved claims far in the past/future
	custom := map[string]string{
		"iat":  "1",
		"nbf":  "1",
		"exp":  "9999999999",
		"role": "user",
	}

	// Set cookie
	err = cm.SetJWTCookie(w, r, custom)
	assert.NoError(err)

	// Validate and inspect effective claims
	cookie := w.Result().Cookies()[0]
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)

	claims, err := cm.GetClaimsOfValid(r2)
	assert.NoError(err)

	// Verify reserved claims are numbers (from server) not strings from custom input
	_, iatIsFloat := claims["iat"].(float64)
	_, nbfIsFloat := claims["nbf"].(float64)
	_, expIsFloat := claims["exp"].(float64)
	assert.True(iatIsFloat)
	assert.True(nbfIsFloat)
	assert.True(expIsFloat)

	// Also check role made it through unchanged
	assert.Equal("user", claims["role"])
}
