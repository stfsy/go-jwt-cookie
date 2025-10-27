package jwtcookie

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

// Typed signing key helpers for type-safety
// WithSigningKeyHMAC sets an HMAC signing key (HS256/HS384/HS512) and an optional kidSalt for KID derivation.
// Note: Minimum HMAC key lengths are enforced by NewCookieManager based on the selected method:
// - HS256: at least 32 bytes
// - HS384: at least 48 bytes
// - HS512: at least 64 bytes
// The signing key must satisfy the minimum for the configured signing method.
// KID derivation behavior:
//   - If kidSalt is provided and non-empty, KID = base64url(HMAC-SHA256(kidSalt, key)[:16])
//   - If kidSalt is nil or empty, KID = base64url(HMAC-SHA256(empty_key, key)[:16]) i.e., HMAC with an empty key
//     (note: this is NOT plain SHA-256(key)).
//
// The salt value is copied into the CookieManager as provided (nil remains nil; empty remains empty).
func WithSigningKeyHMAC(key []byte, kidSalt []byte) Option {
	return func(cm *CookieManager) {
		cm.signingKey = key
		cm.kidSalt = append([]byte(nil), kidSalt...)
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

// WithTimeFunc sets a custom time source for JWT validation. Useful for tests or
// environments with controlled time sources. If not set, time.Now is used by the
// jwt library internally. Combine with a small leeway to account for skew.
func WithTimeFunc(fn func() time.Time) Option {
	return func(cm *CookieManager) {
		cm.timeFunc = fn
	}
}

// WithLeeway configures a positive leeway duration for validating exp/nbf/iat claims,
// useful to absorb minor clock skews between services. If d <= 0, no leeway is applied.
func WithLeeway(d time.Duration) Option {
	return func(cm *CookieManager) {
		cm.leeway = d
	}
}
