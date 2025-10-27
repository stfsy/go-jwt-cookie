# Copilot Coding Agent Instructions — go-jwt-cookie

Scope and intent
- Single Go package `jwtcookie` for issuing JWTs and setting/reading them via HTTP cookies. Keep edits minimal, preserve security checks, and run tests.

Key files
- `cookie.go` — CookieManager, SetJWTCookie, GetClaimsOfValid, KID logic
- `options.go` — functional options (`WithXxx`), typed signing/validation helpers, leeway/time
- `cookie_test.go`, `kid_header_test.go` — unit tests; `cookie_fuzz_test.go` — fuzz tests
- `test.sh` (vet + tests, 2s timeout), `fuzz.sh`, `lint.sh`

Architecture and API essentials
- Construct with `NewCookieManager(opts...) (*CookieManager, error)`; validates config at construction.
- Required: `WithIssuer(...)`, `WithAudience(...)`, a signing method, a signing key, and at least one typed validation key matching the method (HMAC/RSA/ECDSA).
- Defaults: cookieName="jwt_token", secure=true, httpOnly=true, maxAge=3600s, sameSite=Strict, path="/".
- `SetJWTCookie(w, r, custom map[string]string)` adds server-controlled claims `iat/nbf/exp/iss/aud` and refuses any non-alphanumeric claim keys/values (allowed charset: A–Z a–z 0–9 _ + -).
- `GetClaimsOfValid(r)` reads the cookie, validates strictly against the configured alg/iss/aud using a cached jwt.Parser, tries KID match first, then other validation keys; returns `map[string]interface{}`.

Signing, KID, and rotation
- HMAC: min key sizes enforced — HS256≥32B, HS384≥48B, HS512≥64B. KID = base64url(HMAC-SHA256(kidSalt, key)[:16]); kidSalt required (non-empty). Use `WithSigningKeyHMAC(key, kidSalt)` and `WithValidationKeysHMAC([...])`.
	- Use a cryptographically random salt ≥16 bytes (32 bytes preferred).
	- Keep the salt consistent across signers/validators; rotating it changes KIDs for new tokens. Old tokens still validate via key iteration, but fast KID lookup is lost until all parties align.
	- Store salt alongside other secrets (env vars or a secret manager). Don’t hard-code in source or expose to clients.
- RSA/RSAPSS/ECDSA: use `WithSigningKeyRSA/*ECDSA` and corresponding `WithValidationKeys*`. KID = base64url(SHA-256(SPKI)[:16]). Exact alg match is enforced (e.g., PS256 ≠ RS256).

Project conventions and patterns
- Functional options pattern with typed helpers: `WithSigningMethodHS256/RS256/PS256/ES256` etc.; prefer typed validation key helpers for rotation.
- Claims are simple strings in `SetJWTCookie`; reserved claims from callers are overwritten by server values.
- Optional time controls: `WithLeeway(d)` for exp/nbf/iat skew, `WithTimeFunc(fn)` for deterministic tests.
- Tests use `testify` and small RSA keys (1024-bit) to meet the 2s timeout; fuzz tests target cookie set/get.

Developer workflows
- Build: `go build ./...`
- Tests: run `./test.sh` (includes `go vet`; CI adds `-race`).
- Fuzz: `./fuzz.sh` (per-target with -fuzztime); Lint: `./lint.sh` (dockerized golangci-lint).
- Go toolchain: see `go.mod` (go 1.24.5) — use a compatible version.

Pitfalls to avoid (common failure modes)
- Missing iss/aud, missing validation keys, or mismatched alg/keys will error at construction or validation.
- HMAC keys too short; empty kidSalt; non-alphanumeric custom claim keys/values; ECDSA curve not matching selected ES* method.

Commit style
- Conventional Commits, e.g., `feat(options): add WithLeeway`, `fix(cookie): enforce alphanumeric custom claims`.
```