package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestTypedHelpers_HMAC_SetFields(t *testing.T) {
	assert := assert.New(t)
	// HMAC
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cm, err := NewCookieManager(WithSigningKeyHMAC(hmacKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"))
	assert.NoError(err)
	assert.Equal(hmacKey, cm.signingKey)
	assert.Equal(jwt.SigningMethodHS256, cm.signingMethod)
}

func TestTypedHelpers_RSA_SetFields(t *testing.T) {
	assert := assert.New(t)
	// RSA
	privRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(err)
	cmRSA, err := NewCookieManager(WithSigningKeyRSA(privRSA), WithSigningMethodRS256(), WithValidationKeysRSA([]*rsa.PublicKey{&privRSA.PublicKey}), WithIssuer("iss"), WithAudience("aud"))
	assert.NoError(err)
	assert.Equal(privRSA, cmRSA.signingKey)
	assert.Equal(jwt.SigningMethodRS256, cmRSA.signingMethod)
}

func TestTypedHelpers_ECDSA_SetFields(t *testing.T) {
	assert := assert.New(t)
	// ECDSA
	privECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	cmECDSA, err := NewCookieManager(WithSigningKeyECDSA(privECDSA), WithSigningMethodES256(), WithValidationKeysECDSA([]*ecdsa.PublicKey{&privECDSA.PublicKey}), WithIssuer("iss"), WithAudience("aud"))
	assert.NoError(err)
	assert.Equal(privECDSA, cmECDSA.signingKey)
	assert.Equal(jwt.SigningMethodES256, cmECDSA.signingMethod)
}

func TestTypedHelpers_CookieOptions(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cmOpts, err := NewCookieManager(WithSecure(false), WithHTTPOnly(false), WithMaxAge(1234), WithSameSite(http.SameSiteLaxMode), WithCookieName("mycookie"), WithSigningKeyHMAC(hmacKey, []byte("0123456789abcdef")), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}), WithIssuer("iss"), WithAudience("aud"))
	assert.NoError(err)
	assert.False(cmOpts.secure)
	assert.False(cmOpts.httpOnly)
	assert.Equal(1234, cmOpts.maxAge)
	assert.Equal(http.SameSiteLaxMode, cmOpts.sameSite)
	assert.Equal("mycookie", cmOpts.cookieName)
}
