package jwtcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCookieManager_Defaults(t *testing.T) {
	cm := NewCookieManager()

	assert.False(t, cm.secure)
	assert.True(t, cm.httpOnly)
	assert.Equal(t, 3600, cm.maxAge)
	assert.Equal(t, http.SameSiteLaxMode, cm.sameSite)
	assert.Equal(t, "/", cm.path)
	assert.Equal(t, "jwt_token", cm.cookieName)
	assert.NotNil(t, cm.secretKey)
}

func TestNewCookieManager_WithOptions(t *testing.T) {
	secretKey := []byte("test-secret-key")
	cm := NewCookieManager(
		WithSecure(true),
		WithHTTPOnly(false),
		WithMaxAge(7200),
		WithSameSite(http.SameSiteStrictMode),
		WithDomain("example.com"),
		WithPath("/api"),
		WithCookieName("custom_token"),
		WithSecretKey(secretKey),
	)

	assert.True(t, cm.secure)
	assert.False(t, cm.httpOnly)
	assert.Equal(t, 7200, cm.maxAge)
	assert.Equal(t, http.SameSiteStrictMode, cm.sameSite)
	assert.Equal(t, "example.com", cm.domain)
	assert.Equal(t, "/api", cm.path)
	assert.Equal(t, "custom_token", cm.cookieName)
	assert.Equal(t, secretKey, cm.secretKey)
}

func TestSetJWTCookie_BasicFunctionality(t *testing.T) {
	cm := NewCookieManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id": "12345",
		"role":    "admin",
	}

	err := cm.SetJWTCookie(w, r, customClaims)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, "jwt_token", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, 3600, cookie.MaxAge)
	assert.True(t, cookie.HttpOnly)
	assert.False(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}

func TestSetJWTCookie_CustomClaims(t *testing.T) {
	secretKey := []byte("test-secret-key")
	cm := NewCookieManager(WithSecretKey(secretKey))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	customClaims := map[string]string{
		"user_id":  "12345",
		"role":     "admin",
		"username": "testuser",
	}

	err := cm.SetJWTCookie(w, r, customClaims)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	// Parse and verify the JWT token
	token, err := jwt.Parse(cookies[0].Value, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// Verify custom claims
	assert.Equal(t, "12345", claims["user_id"])
	assert.Equal(t, "admin", claims["role"])
	assert.Equal(t, "testuser", claims["username"])

	// Verify standard claims exist
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["nbf"])
}

func TestSetJWTCookie_StandardClaims(t *testing.T) {
	secretKey := []byte("test-secret-key")
	cm := NewCookieManager(WithSecretKey(secretKey), WithMaxAge(7200))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	beforeTime := time.Now().Unix()
	err := cm.SetJWTCookie(w, r, map[string]string{})
	afterTime := time.Now().Unix()
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	// Parse the JWT token
	token, err := jwt.Parse(cookies[0].Value, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// Verify iat (issued at) is within reasonable time range
	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	assert.GreaterOrEqual(t, int64(iat), beforeTime)
	assert.LessOrEqual(t, int64(iat), afterTime)

	// Verify exp (expiration) is iat + maxAge
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	assert.GreaterOrEqual(t, int64(exp), beforeTime+7200)
	assert.LessOrEqual(t, int64(exp), afterTime+7200)

	// Verify nbf (not before) is set to iat
	nbf, ok := claims["nbf"].(float64)
	require.True(t, ok)
	assert.Equal(t, int64(iat), int64(nbf))
}

func TestSetJWTCookie_EmptyCustomClaims(t *testing.T) {
	cm := NewCookieManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err := cm.SetJWTCookie(w, r, map[string]string{})
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.NotEmpty(t, cookies[0].Value)
}

func TestSetJWTCookie_NilCustomClaims(t *testing.T) {
	cm := NewCookieManager()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err := cm.SetJWTCookie(w, r, nil)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.NotEmpty(t, cookies[0].Value)
}

func TestSetJWTCookie_CustomCookieOptions(t *testing.T) {
	cm := NewCookieManager(
		WithSecure(true),
		WithHTTPOnly(false),
		WithMaxAge(1800),
		WithSameSite(http.SameSiteStrictMode),
		WithDomain("example.com"),
		WithPath("/api"),
		WithCookieName("custom_jwt"),
	)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	err := cm.SetJWTCookie(w, r, map[string]string{"test": "value"})
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, "custom_jwt", cookie.Name)
	assert.True(t, cookie.Secure)
	assert.False(t, cookie.HttpOnly)
	assert.Equal(t, 1800, cookie.MaxAge)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	assert.Equal(t, "example.com", cookie.Domain)
	assert.Equal(t, "/api", cookie.Path)
}

func TestSetJWTCookie_TokenSignature(t *testing.T) {
	secretKey1 := []byte("secret-key-1")
	secretKey2 := []byte("secret-key-2")

	cm1 := NewCookieManager(WithSecretKey(secretKey1))
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)

	err := cm1.SetJWTCookie(w1, r1, map[string]string{"user": "test"})
	require.NoError(t, err)

	token1 := w1.Result().Cookies()[0].Value

	// Token signed with secretKey1 should be valid with secretKey1
	parsedToken1, err := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return secretKey1, nil
	})
	require.NoError(t, err)
	assert.True(t, parsedToken1.Valid)

	// Token signed with secretKey1 should NOT be valid with secretKey2
	parsedToken2, err := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return secretKey2, nil
	})
	assert.Error(t, err)
	assert.False(t, parsedToken2.Valid)
}
