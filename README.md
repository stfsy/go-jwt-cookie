# go-jwt-cookie

An opinionated Go package for creating JWT tokens and setting them as HTTP cookies with configurable security options.

This library is intended to support your existing **session management**. It offers:

- JWT token signing with standard and custom claims
- JWT token validation and claims extraction
- Configurable cookie options (Secure, HttpOnly, SameSite, etc.)
- Signing key rotation support for seamless key updates
- Simple constructor-based configuration pattern

The library itself does not provide any **session management** mechanism for managing session metadata, invalidation, or expiration.

## Why use it
In most web applications you need to manage user sessions. Storing a session ID in a signed JWT in an HTTP-only, Secure cookie allows you to verify the integrity of the JWT directly on the server (without a database lookup). Thus, you can safely reject tampered tokens without needing to query a backend store.

This approach doesn’t prevent you from storing session metadata in a database. In fact, combining both is recommended: keep a server-side session record so you can invalidate sessions, track activity, and implement logout and forced expiration. Note that JWTs are signed, not encrypted—don’t place secrets in claims.

## Installation

Use the module path shown in `go.mod`:

```bash
go get github.com/stfsy/go-jwt-cookie
```

## Quick Usage

The simplest integration is to create a cookie manager and use it to set JWT cookies:

```go
package main

import (
	"net/http"
	"time"

	"github.com/stfsy/go-jwt-cookie"
)

func main() {
    // Create a cookie manager with secure options
     manager := jwtcookie.NewCookieManager(
	 	jwtcookie.WithSecure(true),
	 	jwtcookie.WithHTTPOnly(true),
      	// kidSalt (second argument) is required and influences deterministic KID derivation for HMAC keys.
      	// Use a secret, random, non-empty salt consistent across instances. Minimum 16 bytes recommended (32 bytes preferred).
      	jwtcookie.WithSigningKeyHMAC(
      		[]byte("production-signing-key-that-is-at-least-32-bytes-long"),
      		[]byte("0123456789abcdef"), // 16-byte salt example; prefer 32 random bytes in production
      	),
	 	jwtcookie.WithSigningMethod(jwt.SigningMethodHS256),
	 	jwtcookie.WithIssuer("https://my-signing-service-url.domain"),
	 	jwtcookie.WithAudience("https://my-validating-service-url.domain"),
	 )

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Create custom claims
		claims := map[string]string{
			"user_id": "12345",
			"role":    "admin",
		}

		// Set JWT cookie
		err := manager.SetJWTCookie(w, r, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("JWT cookie set successfully"))
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		// Validate JWT and get claims
		claims, err := manager.GetClaimsOfValid(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userID := claims["user_id"]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome, user: " + userID.(string)))
	})

	http.ListenAndServe(":8080", nil)
}
```

## Key Rotation

The library supports signing key rotation, allowing you to validate tokens signed with old keys while signing new tokens with a new key:

```go
oldKey := []byte("old-signing-key")
newKey := []byte("new-signing-key")

manager := jwtcookie.NewCookieManager(
	// Use a secret salt of at least 16 bytes (32 preferred) and keep it consistent across instances
	jwtcookie.WithSigningKeyHMAC(newKey, []byte("0123456789abcdef")),  // 16-byte salt example; prefer 32 random bytes in production
	jwtcookie.WithValidationKeysHMAC([][]byte{newKey, oldKey}),  // Accept both keys for validation
 	jwtcookie.WithSigningMethod(jwt.SigningMethodHS256),
 	jwtcookie.WithIssuer("your-service-name"),
 	jwtcookie.WithAudience("your-frontend-app"),
)

// New tokens will be signed with newKey
// Old tokens signed with oldKey will still validate successfully
```

## RSA and ECDSA Examples

### Using RSA Keys

```go
import (
	"crypto/rand"
	"crypto/rsa"
	
	"github.com/golang-jwt/jwt/v5"
	"github.com/stfsy/go-jwt-cookie"
)

// Generate RSA key pair
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

manager := jwtcookie.NewCookieManager(
	jwtcookie.WithSigningKeyRSA(privateKey),
	jwtcookie.WithSigningMethod(jwt.SigningMethodRS256),
	jwtcookie.WithIssuer("your-service-name"),
	jwtcookie.WithAudience("your-frontend-app"),
)

// For validation with public keys only
manager := jwtcookie.NewCookieManager(
	jwtcookie.WithSigningKeyRSA(privateKey),
	jwtcookie.WithSigningMethod(jwt.SigningMethodRS256),
	jwtcookie.WithValidationKeysRSA([]*rsa.PublicKey{&privateKey.PublicKey}),
	jwtcookie.WithIssuer("your-service-name"),
	jwtcookie.WithAudience("your-frontend-app"),
)

// Example: RSA-PSS (RSAPSS) using PS256
// Use the RSA private key for signing with RSAPSS (PS256)
managerPS, _ := jwtcookie.NewCookieManager(
	jwtcookie.WithSigningKeyRSA(privateKey),
	jwtcookie.WithSigningMethodPS256(),
	jwtcookie.WithValidationKeysRSA([]*rsa.PublicKey{&privateKey.PublicKey}),
	jwtcookie.WithIssuer("your-service-name"),
	jwtcookie.WithAudience("your-frontend-app"),
)
```

### Using ECDSA Keys

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	
	"github.com/golang-jwt/jwt/v5"
	"github.com/stfsy/go-jwt-cookie"
)

// Generate ECDSA key pair
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

manager := jwtcookie.NewCookieManager(
	jwtcookie.WithSigningKeyECDSA(privateKey),
	jwtcookie.WithSigningMethod(jwt.SigningMethodES256),
	jwtcookie.WithIssuer("your-service-name"),
	jwtcookie.WithAudience("your-frontend-app"),
)
```
```

## Configuration Options

The cookie manager supports the following configuration options:

- `WithSecure(bool)` — sets the Secure flag on the cookie (HTTPS only)
- `WithHTTPOnly(bool)` — sets the HttpOnly flag to prevent JavaScript access
- `WithMaxAge(int)` — sets cookie expiration in seconds
- `WithSameSite(http.SameSite)` — sets the SameSite attribute
- `WithDomain(string)` — sets the cookie domain
- `WithPath(string)` — sets the cookie path
- `WithCookieName(string)` — sets a custom cookie name
- `WithSigningKeyHMAC([]byte, []byte)`, `WithSigningKeyRSA(*rsa.PrivateKey)`, `WithSigningKeyECDSA(*ecdsa.PrivateKey)` — typed helpers to set the signing key for signing JWTs
	- For HMAC (HS256, HS384, HS512): use `WithSigningKeyHMAC(key, kidSalt)` where `kidSalt` is required (non-empty). The KID is derived as `base64url(HMAC-SHA256(kidSalt, key)[:16])`. Use a secret, random salt consistent across instances.
	- For RSA (RS256, RS384, RS512, PS256, PS384, PS512): use `WithSigningKeyRSA(*rsa.PrivateKey)`
	- For ECDSA (ES256, ES384, ES512): use `WithSigningKeyECDSA(*ecdsa.PrivateKey)`
- `WithIssuer(string)`, `WithAudience(string)`  — required; used for iss/aud/sub claims and enforced during validation
- `WithValidationKeysHMAC([][]byte)`, `WithValidationKeysRSA([]*rsa.PublicKey)`, `WithValidationKeysECDSA([]*ecdsa.PublicKey)` — typed helpers to set multiple keys for validation (supports key rotation)
	- For HMAC: pass `WithValidationKeysHMAC([][]byte)`
	- For RSA: pass `WithValidationKeysRSA([]*rsa.PublicKey)`
	- For ECDSA: pass `WithValidationKeysECDSA([]*ecdsa.PublicKey)`
- `WithSigningMethod(jwt.SigningMethod)` — sets the JWT signing algorithm
  - HMAC: HS256 (default), HS384, HS512
  - RSA: RS256, RS384, RS512, PS256, PS384, PS512
  - ECDSA: ES256, ES384, ES512
- `WithLeeway(time.Duration)` — optionally applies a clock-skew leeway during validation for `exp`/`nbf`/`iat` claims. If unset or <= 0, no leeway is applied. Example: `WithLeeway(30*time.Second)`.
- `WithTimeFunc(func() time.Time)` — optionally injects a custom time source for validation (useful for tests or controlled environments). When not provided, the default time source is used.

## Testing

Unit tests are provided and can be run with:

```bash
go test ./...
```

Or use the included test script:

```bash
./test.sh
```

## Fuzzing

Fuzz tests are provided to ensure robustness. Run them with:

```bash
./fuzz.sh
```

## Security Considerations

- Always use `WithSecure(true)` in production to ensure cookies are only sent over HTTPS
- Use `WithHTTPOnly(true)` to prevent XSS attacks from accessing the token
- Consider using `WithSameSite(http.SameSiteStrictMode)` to prevent CSRF attacks
- Use a strong signing key for signing JWT tokens
- Use `WithSigningMethod()` to select an appropriate algorithm (HS256, HS384, HS512; or RS*/PS*/ES*)
- Provide `WithIssuer`, `WithAudience` and keep them consistent across services; tokens lacking these claims will be rejected.
- For HMAC, ensure keys meet minimum sizes (HS256: 32 bytes, HS384: 48 bytes, HS512: 64 bytes)
- Account for clock skew between services. Consider configuring a small leeway (e.g., 30s) via `WithLeeway(30*time.Second)`.

## Contributing

1. Fork the repository and create a branch.
2. Run tests and linters locally using `test.sh` and `lint.sh`.
3. Make a small, focused change with corresponding tests.
4. Open a PR with a clear description.

## License

MIT
