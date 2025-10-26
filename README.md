# go-jwt-cookie

A lightweight Go package for creating JWT tokens and setting them as HTTP cookies with configurable security options.

This library is intended to be embedded into HTTP servers for authentication and session management. It offers:

- JWT token generation with standard and custom claims
- JWT token validation and claims extraction
- Configurable cookie options (secure, httpOnly, sameSite, etc.)
- Secret key rotation support for seamless key updates
- Simple constructor-based configuration pattern

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
		jwtcookie.WithSigningKey([]byte("production-signing-key")),
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
	jwtcookie.WithSigningKey(newKey),  // New key for signing
	jwtcookie.WithValidationKeys([][]byte{newKey, oldKey}),  // Accept both keys for validation
)

// New tokens will be signed with newKey
// Old tokens signed with oldKey will still validate successfully
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
- `WithSigningKey([]byte)` — sets the signing key for signing JWTs
- `WithValidationKeys([][]byte)` — sets multiple signing keys for validation (supports key rotation)
- `WithSigningMethod(jwt.SigningMethod)` — sets the JWT signing algorithm (default: HS256; supported: HS256, HS384, HS512)

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
- Use `WithSigningMethod()` to select an appropriate algorithm (HS256, HS384, or HS512)

## Contributing

1. Fork the repository and create a branch.
2. Run tests and linters locally using `test.sh` and `lint.sh`.
3. Make a small, focused change with corresponding tests.
4. Open a PR with a clear description.

## License

MIT