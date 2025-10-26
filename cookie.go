package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CookieManager manages JWT cookie creation and configuration
type CookieManager struct {
	secure     bool
	httpOnly   bool
	maxAge     int
	sameSite   http.SameSite
	domain     string
	path       string
	cookieName string
	issuer     string
	audience   string
	subject    string
	signingKey interface{} // Used for signing ([]byte for HMAC, *rsa.PrivateKey for RSA, *ecdsa.PrivateKey for ECDSA)
	// Typed validation keys for key rotation (avoid boxing/rt type assertions)
	validationKeysHMAC   [][]byte
	validationKeysRSA    []*rsa.PublicKey
	validationKeysECDSA  []*ecdsa.PublicKey
	signingMethod        jwt.SigningMethod // JWT signing algorithm
	parser               *jwt.Parser       // cached parser with configured validation options
	signingKeyKID        string
	validationHMACByKID  map[string][]byte
	validationRSAByKID   map[string]*rsa.PublicKey
	validationECDSAByKID map[string]*ecdsa.PublicKey
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

// WithIssuer sets the issuer (iss) claim that must be present in tokens
func WithIssuer(issuer string) Option {
	return func(cm *CookieManager) {
		cm.issuer = issuer
	}
}

// WithAudience sets the audience (aud) claim that must be present in tokens
func WithAudience(audience string) Option {
	return func(cm *CookieManager) {
		cm.audience = audience
	}
}

// WithSubject sets the subject (sub) claim that must be present in tokens
func WithSubject(subject string) Option {
	return func(cm *CookieManager) {
		cm.subject = subject
	}
}

// Typed signing key helpers for type-safety
// WithSigningKeyHMAC sets an HMAC signing key (HS256/HS384/HS512).
// Note: Minimum HMAC key lengths are enforced by NewCookieManager based on the selected method:
// - HS256: at least 32 bytes
// - HS384: at least 48 bytes
// - HS512: at least 64 bytes
// The signing key must satisfy the minimum for the configured signing method.
func WithSigningKeyHMAC(key []byte) Option {
	return func(cm *CookieManager) {
		cm.signingKey = key
		cm.signingKeyKID = computeKIDFromHMAC(key)
	}
}

// WithSigningKeyRSA sets an RSA signing key (private key for RS*/PS*)
func WithSigningKeyRSA(key *rsa.PrivateKey) Option {
	return func(cm *CookieManager) {
		cm.signingKey = key
	}
}

// WithSigningKeyECDSA sets an ECDSA signing key (private key for ES*)
func WithSigningKeyECDSA(key *ecdsa.PrivateKey) Option {
	return func(cm *CookieManager) {
		cm.signingKey = key
	}
}

// Validation keys (supports key rotation): at least one validation key MUST be provided
// via the typed helpers below; omitting validation keys is an error enforced by NewCookieManager.
// Typed validation key helpers for type-safety
// WithValidationKeysHMAC accepts a slice of HMAC keys.
// Note: Minimum HMAC key lengths are enforced by NewCookieManager based on the selected method:
// - HS256: at least 32 bytes
// - HS384: at least 48 bytes
// - HS512: at least 64 bytes
// All validation keys must satisfy the minimum for the configured signing method.
func WithValidationKeysHMAC(keys [][]byte) Option {
	return func(cm *CookieManager) {
		cm.validationKeysHMAC = keys
	}
}

// WithValidationKeysRSA accepts a slice of RSA public keys
func WithValidationKeysRSA(keys []*rsa.PublicKey) Option {
	return func(cm *CookieManager) {
		cm.validationKeysRSA = keys
	}
}

// WithValidationKeysECDSA accepts a slice of ECDSA public keys
func WithValidationKeysECDSA(keys []*ecdsa.PublicKey) Option {
	return func(cm *CookieManager) {
		cm.validationKeysECDSA = keys
	}
}

// WithSigningMethod sets the JWT signing algorithm (default: HS256)
// Supported methods:
// - HMAC: HS256, HS384, HS512
// - RSA: RS256, RS384, RS512, PS256, PS384, PS512
// - ECDSA: ES256, ES384, ES512
func WithSigningMethod(method jwt.SigningMethod) Option {
	return func(cm *CookieManager) {
		cm.signingMethod = method
	}
}

// Typesafe helpers for signing methods
func WithSigningMethodHS256() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodHS256 }
}
func WithSigningMethodHS384() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodHS384 }
}
func WithSigningMethodHS512() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodHS512 }
}

func WithSigningMethodRS256() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodRS256 }
}
func WithSigningMethodRS384() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodRS384 }
}
func WithSigningMethodRS512() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodRS512 }
}

func WithSigningMethodPS256() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodPS256 }
}
func WithSigningMethodPS384() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodPS384 }
}
func WithSigningMethodPS512() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodPS512 }
}

func WithSigningMethodES256() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodES256 }
}
func WithSigningMethodES384() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodES384 }
}
func WithSigningMethodES512() Option {
	return func(cm *CookieManager) { cm.signingMethod = jwt.SigningMethodES512 }
}

// NewCookieManager creates a new CookieManager with the given options
func NewCookieManager(opts ...Option) (*CookieManager, error) {
	// Set defaults
	cm := &CookieManager{
		secure:     true,
		httpOnly:   true,
		maxAge:     3600, // 1 hour default
		sameSite:   http.SameSiteStrictMode,
		path:       "/",
		cookieName: "jwt_token",
	}

	// Apply options
	for _, opt := range opts {
		opt(cm)
	}

	// Require standard identity claims to be configured
	if cm.issuer == "" {
		return nil, fmt.Errorf("issuer (iss) must be specified")
	}
	if cm.audience == "" {
		return nil, fmt.Errorf("audience (aud) must be specified")
	}
	if cm.subject == "" {
		return nil, fmt.Errorf("subject (sub) must be specified")
	}

	if cm.signingMethod == nil {
		return nil, fmt.Errorf("signing method must be specified")
	} else if cm.signingKey == nil {
		return nil, fmt.Errorf("signing key must be specified")
	} else if cm.signingMethod == jwt.SigningMethodHS256 ||
		cm.signingMethod == jwt.SigningMethodHS384 ||
		cm.signingMethod == jwt.SigningMethodHS512 {
		if len(cm.validationKeysHMAC) == 0 {
			return nil, fmt.Errorf("at least one validation key must be specified")
		}
		keyBytes, ok := cm.signingKey.([]byte)
		if !ok {
			return nil, fmt.Errorf("HMAC signing method requires []byte signing key")
		}

		// Enforce minimum HMAC key sizes per algorithm
		var minLen int
		switch cm.signingMethod {
		case jwt.SigningMethodHS256:
			minLen = 32 // 256 bits
		case jwt.SigningMethodHS384:
			minLen = 48 // 384 bits
		case jwt.SigningMethodHS512:
			minLen = 64 // 512 bits
		}
		if len(keyBytes) < minLen {
			return nil, fmt.Errorf("HMAC signing key too short for %s: got %d bytes, require at least %d bytes", cm.signingMethod.Alg(), len(keyBytes), minLen)
		}
		for _, kb := range cm.validationKeysHMAC {
			if len(kb) < minLen {
				return nil, fmt.Errorf("HMAC validation key too short for %s: got %d bytes, require at least %d bytes", cm.signingMethod.Alg(), len(kb), minLen)
			}
		}
	} else if cm.signingMethod == jwt.SigningMethodRS256 ||
		cm.signingMethod == jwt.SigningMethodRS384 ||
		cm.signingMethod == jwt.SigningMethodRS512 ||
		cm.signingMethod == jwt.SigningMethodPS256 ||
		cm.signingMethod == jwt.SigningMethodPS384 ||
		cm.signingMethod == jwt.SigningMethodPS512 {
		if len(cm.validationKeysRSA) == 0 {
			return nil, fmt.Errorf("at least one validation key must be specified")
		}
		if _, ok := cm.signingKey.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("RSA signing method requires *rsa.PrivateKey signing key")
		}
		// validation keys are typed; no runtime checks needed here
	} else if cm.signingMethod == jwt.SigningMethodES256 ||
		cm.signingMethod == jwt.SigningMethodES384 ||
		cm.signingMethod == jwt.SigningMethodES512 {
		if len(cm.validationKeysECDSA) == 0 {
			return nil, fmt.Errorf("at least one validation key must be specified")
		}
		if _, ok := cm.signingKey.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("ECDSA signing method requires *ecdsa.PrivateKey signing key")
		}
		// validation keys are typed; no runtime checks needed here
	}

	// Build and cache a JWT parser configured with fixed validation options
	cm.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{cm.signingMethod.Alg()}),
		jwt.WithIssuer(cm.issuer),
		jwt.WithAudience(cm.audience),
		jwt.WithSubject(cm.subject),
	)

	// Prepare KID maps for fast lookup
	switch cm.signingMethod {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		// Compute KID for signing key and validation keys
		cm.validationHMACByKID = make(map[string][]byte, len(cm.validationKeysHMAC))
		for _, k := range cm.validationKeysHMAC {
			cm.validationHMACByKID[computeKIDFromHMAC(k)] = k
		}
		if sk, ok := cm.signingKey.([]byte); ok && len(sk) > 0 {
			cm.signingKeyKID = computeKIDFromHMAC(sk)
		}
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512, jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512:
		cm.validationRSAByKID = make(map[string]*rsa.PublicKey, len(cm.validationKeysRSA))
		for _, pk := range cm.validationKeysRSA {
			kid, err := computeKIDFromPublicKey(pk)
			if err != nil {
				return nil, fmt.Errorf("failed to compute KID from RSA public key: %w", err)
			}
			cm.validationRSAByKID[kid] = pk
		}
		if pk, ok := cm.signingKey.(*rsa.PrivateKey); ok {
			kid, err := computeKIDFromPublicKey(&pk.PublicKey)
			if err == nil {
				cm.signingKeyKID = kid
			}
			cm.signingKeyKID = kid
		}
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		cm.validationECDSAByKID = make(map[string]*ecdsa.PublicKey, len(cm.validationKeysECDSA))
		for _, pk := range cm.validationKeysECDSA {
			if kid, err := computeKIDFromPublicKey(pk); err == nil {
				cm.validationECDSAByKID[kid] = pk
			}
		}
		if pk, ok := cm.signingKey.(*ecdsa.PrivateKey); ok {
			if kid, err := computeKIDFromPublicKey(&pk.PublicKey); err == nil {
				cm.signingKeyKID = kid
			}
		}
	}

	return cm, nil
}

// SetJWTCookie creates a JWT token with the provided claims and sets it as an HTTP cookie
func (cm *CookieManager) SetJWTCookie(w http.ResponseWriter, r *http.Request, customClaims map[string]string) error {
	// Create JWT claims with standard fields
	now := time.Now()
	claims := make(jwt.MapClaims, len(customClaims)+6)

	// Add custom claims first (may include reserved names); we'll re-assert reserved ones below
	for key, value := range customClaims {
		claims[key] = value
	}

	// Re-assert server-controlled standard claims to prevent override by callers
	claims["iat"] = now.Unix()                                             // Issued at
	claims["nbf"] = now.Unix()                                             // Not before
	claims["exp"] = now.Add(time.Duration(cm.maxAge) * time.Second).Unix() // Expiration time
	claims["iss"] = cm.issuer                                              // Issuer
	claims["aud"] = cm.audience                                            // Audience
	claims["sub"] = cm.subject                                             // Subject
	// when adding new claims, update also the preallocated map size above

	// Create the JWT token
	token := jwt.NewWithClaims(cm.signingMethod, claims)
	// Set KID header to allow fast key selection during validation
	if cm.signingKeyKID != "" {
		token.Header["kid"] = cm.signingKeyKID
	}

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

	// Try to validate with each key (supports key rotation). If KID is present, try that key first.
	var lastErr error
	kid, _ := parseKID(tokenString)

	switch cm.signingMethod {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		if kid != "" {
			if publicKey, ok := cm.validationHMACByKID[kid]; ok {
				if publicKey != nil {
					if claims, err := validateWithKey(cm, tokenString, publicKey); err == nil {
						return claims, nil
					} else {
						lastErr = err
					}
				}
			}
		}
		// Fall back to iterating remaining keys
		for _, key := range cm.validationKeysHMAC {
			if claims, err := validateWithKey(cm, tokenString, key); err == nil {
				return claims, nil
			} else {
				lastErr = err
			}
		}
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512, jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512:
		if kid != "" {
			publicKey := cm.validationRSAByKID[kid]
			if publicKey != nil {
				if claims, err := validateWithKey(cm, tokenString, publicKey); err == nil {
					return claims, nil
				} else {
					lastErr = err
				}
			}
		}

		// Fall back to iterating remaining keys
		for _, key := range cm.validationKeysRSA {
			if claims, err := validateWithKey(cm, tokenString, key); err == nil {
				return claims, nil
			} else {
				lastErr = err
			}
		}
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		if kid != "" {
			publicKey := cm.validationECDSAByKID[kid]
			if publicKey != nil {
				if claims, err := validateWithKey(cm, tokenString, publicKey); err == nil {
					return claims, nil
				} else {
					lastErr = err
				}
			}
		}

		// Fall back to iterating remaining keys
		for _, key := range cm.validationKeysECDSA {
			if claims, err := validateWithKey(cm, tokenString, key); err == nil {
				return claims, nil
			} else {
				lastErr = err
			}
		}
	default:
		return nil, fmt.Errorf("unexpected signing method: %v", cm.signingMethod.Alg())
	}

	// None of the keys validated the token
	if lastErr != nil {
		return nil, fmt.Errorf("failed to validate token: %w", lastErr)
	}
	return nil, fmt.Errorf("token is invalid")
}

// Shared helper to validate with a single key and return claims
func validateWithKey(cm *CookieManager, tokenString string, key interface{}) (map[string]interface{}, error) {
	token, err := cm.parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return key, nil })
	if err == nil && token.Valid {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("failed to parse claims")
		}
		return map[string]interface{}(claims), nil
	}
	return nil, err
}

// computeKIDFromHMAC returns a stable, short KID for an HMAC key by hashing the raw key with SHA-256
// and encoding only the first 8 bytes (64 bits) using base64url (no padding).
func computeKIDFromHMAC(key []byte) string {
	sum := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// computeKIDFromPublicKey returns a short KID for a public key by hashing the DER-encoded
// SubjectPublicKeyInfo with SHA-256 and encoding only the first 8 bytes using base64url (no padding).
func computeKIDFromPublicKey(pk any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8]), nil
}

// parseKID extracts the kid field from the JWT header without verifying the token.
func parseKID(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("malformed token")
	}
	headerB64 := parts[0]
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return "", err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", err
	}
	if v, ok := header["kid"]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}
	return "", nil
}
