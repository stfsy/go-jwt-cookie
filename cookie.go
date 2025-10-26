package jwtcookie

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CookieManager manages JWT cookie creation and configuration
type CookieManager struct {
	secure         bool
	httpOnly       bool
	maxAge         int
	sameSite       http.SameSite
	domain         string
	path           string
	cookieName     string
	signingKey     []byte              // Used for signing
	validationKeys [][]byte            // Used for validation (supports key rotation)
	signingMethod  jwt.SigningMethod   // JWT signing algorithm
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

// WithSigningKey sets the signing key for signing JWTs
func WithSigningKey(key []byte) Option {
	return func(cm *CookieManager) {
		cm.signingKey = key
	}
}

// WithValidationKeys sets the signing keys for validating JWTs (supports key rotation)
// If not set, the signing key will be used for validation
func WithValidationKeys(keys [][]byte) Option {
	return func(cm *CookieManager) {
		cm.validationKeys = keys
	}
}

// WithSigningMethod sets the JWT signing algorithm (default: HS256)
// Supported methods: HS256, HS384, HS512
func WithSigningMethod(method jwt.SigningMethod) Option {
	return func(cm *CookieManager) {
		cm.signingMethod = method
	}
}

// NewCookieManager creates a new CookieManager with the given options
func NewCookieManager(opts ...Option) *CookieManager {
	// Set defaults
	cm := &CookieManager{
		secure:        false,
		httpOnly:      true,
		maxAge:        3600, // 1 hour default
		sameSite:      http.SameSiteLaxMode,
		path:          "/",
		cookieName:    "jwt_token",
		signingKey:    []byte("INSECURE-DEFAULT-KEY-PLEASE-CHANGE"), // Should be overridden in production
		signingMethod: jwt.SigningMethodHS256,                       // Default to HS256
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
	token := jwt.NewWithClaims(cm.signingMethod, claims)

	// Sign the token with the signing key
	tokenString, err := token.SignedString(cm.signingKey)
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

// GetClaimsOfValid validates the JWT token from the request cookie and returns the claims
func (cm *CookieManager) GetClaimsOfValid(r *http.Request) (map[string]interface{}, error) {
	// Get the cookie from the request
	cookie, err := r.Cookie(cm.cookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to get cookie: %w", err)
	}

	tokenString := cookie.Value

	// Determine which keys to use for validation
	validationKeys := cm.validationKeys
	if len(validationKeys) == 0 {
		// If no validation keys are set, use the signing key
		validationKeys = [][]byte{cm.signingKey}
	}

	// Try to validate with each key (supports key rotation)
	var lastErr error
	for _, key := range validationKeys {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
		})

		if err == nil && token.Valid {
			// Successfully validated with this key
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("failed to parse claims")
			}

			// Convert jwt.MapClaims to map[string]interface{}
			result := make(map[string]interface{})
			for k, v := range claims {
				result[k] = v
			}
			return result, nil
		}

		lastErr = err
	}

	// None of the keys validated the token
	if lastErr != nil {
		return nil, fmt.Errorf("failed to validate token: %w", lastErr)
	}
	return nil, fmt.Errorf("token is invalid")
}
