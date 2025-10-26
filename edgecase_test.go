package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCookieManager_ValidationErrors(t *testing.T) {
	t.Skip("replaced by dedicated tests")
}

func TestNewCookieManager_MissingSigningMethod(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey), WithValidationKeysHMAC([][]byte{hmacKey}))
	assert.Error(err)
}

func TestNewCookieManager_MissingSigningKey(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}))
	assert.Error(err)
}

func TestNewCookieManager_MissingValidationKeys(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey), WithSigningMethodHS256())
	assert.Error(err)
}

func TestNewCookieManager_HMACWrongKeyType(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyRSA(&rsa.PrivateKey{}), WithSigningMethodHS256(), WithValidationKeysHMAC([][]byte{hmacKey}))
	assert.Error(err)
}

func TestNewCookieManager_RSAWrongSigningKeyType(t *testing.T) {
	assert := assert.New(t)
	hmacKey := []byte("k")
	_, err := NewCookieManager(WithSigningKeyHMAC(hmacKey), WithSigningMethodRS256(), WithValidationKeysHMAC([][]byte{hmacKey}))
	assert.Error(err)
}

func TestNewCookieManager_ECDSAValidationKeysWrongType(t *testing.T) {
	assert := assert.New(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := NewCookieManager(WithSigningKeyECDSA(priv), WithSigningMethodES256(), WithValidationKeysRSA([]*rsa.PublicKey{}))
	assert.Error(err)
}
