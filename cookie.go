package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
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
	signingKey interface{} // Used for signing ([]byte for HMAC, *rsa.PrivateKey for RSA, *ecdsa.PrivateKey for ECDSA)
	// Typed validation keys for key rotation (avoid boxing/rt type assertions)
	validationKeysHMAC   [][]byte
	validationKeysRSA    []*rsa.PublicKey
	validationKeysECDSA  []*ecdsa.PublicKey
	signingMethod        jwt.SigningMethod // JWT signing algorithm
	parser               *jwt.Parser       // cached parser with configured validation options
	signingKeyKID        string
	kidSalt              []byte // optional salt for deriving HMAC KIDs deterministically without exposing raw key material
	validationHMACByKID  map[string][]byte
	validationRSAByKID   map[string]*rsa.PublicKey
	validationECDSAByKID map[string]*ecdsa.PublicKey
	timeFunc             func() time.Time // optional custom time source for parser validations
	leeway               time.Duration    // optional leeway for time-based validations (exp/nbf/iat)
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
		pk, ok := cm.signingKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ECDSA signing method requires *ecdsa.PrivateKey signing key")
		}
		// Enforce curve matches algorithm to avoid runtime signing mismatches
		switch cm.signingMethod {
		case jwt.SigningMethodES256:
			if pk.Curve != elliptic.P256() {
				return nil, fmt.Errorf("ES256 requires P-256 key (got %T)", pk.Curve)
			}
		case jwt.SigningMethodES384:
			if pk.Curve != elliptic.P384() {
				return nil, fmt.Errorf("ES384 requires P-384 key (got %T)", pk.Curve)
			}
		case jwt.SigningMethodES512:
			if pk.Curve != elliptic.P521() {
				return nil, fmt.Errorf("ES512 requires P-521 key (got %T)", pk.Curve)
			}
		}
	}

	// Build and cache a JWT parser configured with fixed validation options
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{cm.signingMethod.Alg()}),
		jwt.WithIssuer(cm.issuer),
		jwt.WithAudience(cm.audience),
	}
	if cm.leeway > 0 {
		parserOpts = append(parserOpts, jwt.WithLeeway(cm.leeway))
	}
	if cm.timeFunc != nil {
		parserOpts = append(parserOpts, jwt.WithTimeFunc(cm.timeFunc))
	}
	cm.parser = jwt.NewParser(parserOpts...)

	// Prepare KID maps for fast lookup
	switch cm.signingMethod {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		// Compute KID for signing key and validation keys
		cm.validationHMACByKID = make(map[string][]byte, len(cm.validationKeysHMAC))
		for _, k := range cm.validationKeysHMAC {
			kid := computeKIDFromSaltedHMAC(cm.kidSalt, k)
			cm.validationHMACByKID[kid] = k
		}

		sk, ok := cm.signingKey.([]byte)
		if !ok {
			return nil, fmt.Errorf("HMAC signing method requires []byte signing key")
		} else if len(sk) == 0 {
			return nil, fmt.Errorf("HMAC signing key cannot be empty")
		} else if len(cm.kidSalt) == 0 {
			return nil, fmt.Errorf("HMAC signing key KID derivation requires non-nil kidSalt for salted KID or empty kidSalt for unsalted KID")
		}

		cm.signingKeyKID = computeKIDFromSaltedHMAC(cm.kidSalt, sk)
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
			if kid, err := computeKIDFromPublicKey(&pk.PublicKey); err == nil {
				cm.signingKeyKID = kid
			}
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

	// verify all claims are alphanumeric keys and values
	for k, v := range customClaims {
		// check key and v are alphanumeric  (incl +,-,_)
		if !isAlphanumeric(k) {
			return fmt.Errorf("claim key '%s' contains non-alphanumeric character", k)
		}
		if !isAlphanumeric(v) {
			return fmt.Errorf("claim value '%s' for key '%s' contains non-alphanumeric character", v, k)
		}
	}

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

// computeKIDFromPublicKey returns a short KID for a public key by hashing the DER-encoded
// SubjectPublicKeyInfo with SHA-256 and encoding the first 16 bytes (128 bits) using base64url (no padding).
func computeKIDFromPublicKey(pk any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

// computeKIDFromSaltedHMAC derives a KID for an HMAC key using HMAC-SHA256 with a caller-provided salt,
// returning base64url encoding of the first 16 bytes (128 bits). This avoids revealing a hash of the raw key.
func computeKIDFromSaltedHMAC(salt, key []byte) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write(key)
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
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
