package jwtcookie

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CookieManager manages JWT cookie creation and configuration
type CookieManager struct {
	secure      bool
	httpOnly    bool
	maxAge      int
	sameSite    http.SameSite
	domain      string
	path        string
	cookieName  string
	secretKey   []byte
}

// Option is a function that configures a CookieManager
type Option func(*CookieManager)

// WithSecure sets the Secure flag on the cookie
func WithSecure(secure bool) Option {
	return func(cm *CookieManager) {
		cm.secure = secure
	}
}

// WithHTTPOnly sets the HttpOnly flag on the cookie
func WithHTTPOnly(httpOnly bool) Option {
	return func(cm *CookieManager) {
		cm.httpOnly = httpOnly
	}
}

// WithMaxAge sets the MaxAge of the cookie in seconds
func WithMaxAge(maxAge int) Option {
	return func(cm *CookieManager) {
		cm.maxAge = maxAge
	}
}

// WithSameSite sets the SameSite attribute of the cookie
func WithSameSite(sameSite http.SameSite) Option {
	return func(cm *CookieManager) {
		cm.sameSite = sameSite
	}
}

// WithDomain sets the Domain attribute of the cookie
func WithDomain(domain string) Option {
	return func(cm *CookieManager) {
		cm.domain = domain
	}
}

// WithPath sets the Path attribute of the cookie
func WithPath(path string) Option {
	return func(cm *CookieManager) {
		cm.path = path
	}
}

// WithCookieName sets the name of the cookie
func WithCookieName(name string) Option {
	return func(cm *CookieManager) {
		cm.cookieName = name
	}
}

// WithSecretKey sets the secret key for signing JWTs
func WithSecretKey(key []byte) Option {
	return func(cm *CookieManager) {
		cm.secretKey = key
	}
}

// NewCookieManager creates a new CookieManager with the given options
func NewCookieManager(opts ...Option) *CookieManager {
	// Set defaults
	cm := &CookieManager{
		secure:     false,
		httpOnly:   true,
		maxAge:     3600, // 1 hour default
		sameSite:   http.SameSiteLaxMode,
		path:       "/",
		cookieName: "jwt_token",
		secretKey:  []byte("default-secret-key"), // Should be overridden in production
	}

	// Apply options
	for _, opt := range opts {
		opt(cm)
	}

	return cm
}

// SetJWTCookie creates a JWT token with the provided claims and sets it as an HTTP cookie
func (cm *CookieManager) SetJWTCookie(w http.ResponseWriter, r *http.Request, customClaims map[string]string) error {
	// Create JWT claims with standard fields
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),                        // Issued at
		"exp": now.Add(time.Duration(cm.maxAge) * time.Second).Unix(), // Expiration time
		"nbf": now.Unix(),                        // Not before
	}

	// Add custom claims from the map
	for key, value := range customClaims {
		claims[key] = value
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(cm.secretKey)
	if err != nil {
		return fmt.Errorf("failed to sign JWT token: %w", err)
	}

	// Create and set the cookie
	cookie := &http.Cookie{
		Name:     cm.cookieName,
		Value:    tokenString,
		Path:     cm.path,
		Domain:   cm.domain,
		MaxAge:   cm.maxAge,
		Secure:   cm.secure,
		HttpOnly: cm.httpOnly,
		SameSite: cm.sameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}
