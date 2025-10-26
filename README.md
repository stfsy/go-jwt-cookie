# go-jwt-cookie

A lightweight Go package for creating JWT tokens and setting them as HTTP cookies with configurable security options.

This library is intended to be embedded into HTTP servers for authentication and session management. It offers:

- JWT token generation with standard and custom claims
- Configurable cookie options (secure, httpOnly, sameSite, etc.)
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
		jwtcookie.WithMaxAge(3600),
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

	http.ListenAndServe(":8080", nil)
}
```

## Configuration Options

The cookie manager supports the following configuration options:

- `WithSecure(bool)` — sets the Secure flag on the cookie (HTTPS only)
- `WithHTTPOnly(bool)` — sets the HttpOnly flag to prevent JavaScript access
- `WithMaxAge(int)` — sets cookie expiration in seconds
- `WithSameSite(http.SameSite)` — sets the SameSite attribute
- `WithDomain(string)` — sets the cookie domain
- `WithPath(string)` — sets the cookie path

## Testing

Unit tests are provided and can be run with:

```bash
go test ./...
```

Or use the included test script:

```bash
./test.sh
```

## Security Considerations

- Always use `WithSecure(true)` in production to ensure cookies are only sent over HTTPS
- Use `WithHTTPOnly(true)` to prevent XSS attacks from accessing the token
- Consider using `WithSameSite(http.SameSiteStrictMode)` to prevent CSRF attacks
- Use a strong secret key for signing JWT tokens

## Contributing

1. Fork the repository and create a branch.
2. Run tests and linters locally using `test.sh` and `lint.sh`.
3. Make a small, focused change with corresponding tests.
4. Open a PR with a clear description.

## License

MIT