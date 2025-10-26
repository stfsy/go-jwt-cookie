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
- Single package, no server: the library provides `NewCookieManager(opts...)` which now returns `(*CookieManager, error)` and validates configuration on construction.
- Internal model: CookieManager holds configuration for cookie attributes (secure, httpOnly, maxAge, sameSite, etc.) and signing keys for signing/validating JWTs.
- JWT tokens include standard claims (iat, exp, nbf) and custom claims provided by the caller.
- Supports key rotation: one key for signing, multiple keys for validation.
- Configurable JWT signing algorithm (HMAC: HS256, HS384, HS512; RSA: RS256, RS384, RS512, PS256, PS384, PS512; ECDSA: ES256, ES384, ES512).

Important behaviors & examples (copy/paste-ready)
- Default cookie settings: httpOnly=true, secure=true, maxAge=3600 (1 hour), sameSite=Strict, path="/"
- Default cookie name: "jwt_token"
- Signing key: set explicitly using typed helpers (see below). The constructor will return an error if signing key/method/validation keys are not correctly provided.
- `SetJWTCookie` creates a JWT with standard claims and custom claims from the provided map, then sets it as an HTTP cookie
- `GetClaimsOfValid` validates a JWT token from the request cookie and returns the claims map
- JWT signing algorithms: 
  - HMAC: HS256, HS384, HS512
  - RSA: RS256, RS384, RS512, PS256, PS384, PS512
  - ECDSA: ES256, ES384, ES512
- Key rotation: use typed helpers to pass validation keys for rotation

Typed helpers (preferred)
- Signing keys:
  - `WithSigningKeyHMAC([]byte)` — HMAC signing key
  - `WithSigningKeyRSA(*rsa.PrivateKey)` — RSA private key for signing (RS*/PS*)
  - `WithSigningKeyECDSA(*ecdsa.PrivateKey)` — ECDSA private key for signing (ES*)
- Validation keys (key rotation):
  - `WithValidationKeysHMAC([][]byte)` — HMAC validation keys
  - `WithValidationKeysRSA([]*rsa.PublicKey)` — RSA public keys for validation
  - `WithValidationKeysECDSA([]*ecdsa.PublicKey)` — ECDSA public keys for validation
- Signing methods (typed helpers): `WithSigningMethodHS256()`, `WithSigningMethodRS256()`, `WithSigningMethodPS256()`, `WithSigningMethodES256()`, etc.

Security notes for agents
- Always recommend using the typed signing-key helpers to set a strong, unique signing key
- Recommend `WithSecure(true)` for production environments (HTTPS)
- Recommend `WithHTTPOnly(true)` to prevent XSS attacks
- Consider `WithSameSite(http.SameSiteStrictMode)` for CSRF protection
- Recommend appropriate signing algorithm based on security requirements (HS256 is acceptable, HS512/RSAPSS/ES512 for higher assurance)

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
- Maintain high test coverage (aim for >80%)
- Add fuzz tests for any new public functions that accept external input
- For RSA key generation in tests, use 1024-bit keys to keep tests fast (2s timeout)

Integration points & dependencies
- `github.com/golang-jwt/jwt/v5` — JWT token generation and signing
- `github.com/stretchr/testify` — testing utilities
- No external server or DB; the package is intended to be embedded in HTTP stacks.

Commit guidelines
- Use Conventional Commits for changes (e.g., `fix(cookie): prevent nil pointer in SetJWTCookie`).
```