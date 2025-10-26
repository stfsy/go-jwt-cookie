# Copilot Coding Agent Instructions — go-jwt-cookie

This repo is a small Go package that implements JWT token generation and HTTP cookie management (package `jwtcookie`). Aim: keep edits minimal, run tests, and respect existing security patterns.

Key files
- `cookie.go` — core implementation (CookieManager, options, SetJWTCookie, GetClaimsOfValid functions)
- `cookie_test.go` — unit tests (uses `testify/assert` and `testify/require`)
- `cookie_fuzz_test.go` — fuzz tests for SetJWTCookie, GetClaimsOfValid, and round-trip testing
- `test.sh` — runs tests: `go test -cover -timeout 2s ./...`
- `fuzz.sh` — runs fuzz tests
- `lint.sh` — runs golangci-lint in Docker

Big picture
- Single package, no server: the library provides `NewCookieManager(opts...)` for creating a cookie manager with configurable options.
- Internal model: CookieManager holds configuration for cookie attributes (secure, httpOnly, maxAge, sameSite, etc.) and secret keys for signing/validating JWTs.
- JWT tokens include standard claims (iat, exp, nbf) and custom claims provided by the caller.
- Supports key rotation: one key for signing, multiple keys for validation.

Important behaviors & examples (copy/paste-ready)
- Default cookie settings: httpOnly=true, secure=false, maxAge=3600 (1 hour), sameSite=Lax, path="/"
- Default cookie name: "jwt_token"
- Default secret key: "INSECURE-DEFAULT-KEY-PLEASE-CHANGE" (should be overridden in production using `WithSecretKey()`)
- `SetJWTCookie` creates a JWT with standard claims and custom claims from the provided map, then sets it as an HTTP cookie
- `GetClaimsOfValid` validates a JWT token from the request cookie and returns the claims map
- JWT signing algorithm: HS256 (HMAC with SHA-256)
- Key rotation: use `WithValidationKeys([][]byte{newKey, oldKey})` to accept multiple keys for validation while signing with the primary key

Security notes for agents
- Always recommend using `WithSecretKey()` to set a strong, unique secret key
- The default secret key is intentionally weak to encourage explicit configuration
- Recommend `WithSecure(true)` for production environments (HTTPS)
- Recommend `WithHTTPOnly(true)` to prevent XSS attacks
- Consider `WithSameSite(http.SameSiteStrictMode)` for CSRF protection

Developer workflows
- Build: `go build ./...`
- Test (quick): `./test.sh` (honors the 2s timeout)
- Fuzz: `./fuzz.sh` (runs fuzz tests for SetJWTCookie, GetClaimsOfValid, and round-trip)
- Lint: `./lint.sh` (dockerized golangci-lint)
- Go version: see `go.mod` (go 1.24.5). Use that or a compatible toolchain.

Patterns to follow when editing
- Keep public API surface minimal: functions/types exported only when needed by consumers.
- Use the functional options pattern for configuration (see existing `WithXxx` functions)
- When adding tests, use `testify/assert` and `testify/require` as in existing tests
- Maintain high test coverage (currently 93.1%)
- Add fuzz tests for any new public functions that accept external input

Integration points & dependencies
- `github.com/golang-jwt/jwt/v5` — JWT token generation and signing
- `github.com/stretchr/testify` — testing utilities
- No external server or DB; the package is intended to be embedded in HTTP stacks.

Commit guidelines
- Use Conventional Commits for changes (e.g., `fix(cookie): prevent nil pointer in SetJWTCookie`).