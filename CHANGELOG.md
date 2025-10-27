# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of JWT cookie creation
- Constructor function for cookie manager with configurable options
- Support for setting cookie secure flag
- Function to create JWT from HTTP request and custom claims map
- `GetClaimsOfValid` function to validate JWT tokens and extract claims
- Signing key rotation support via `WithValidationKeys` option
- Fuzz tests for `SetJWTCookie`, `GetClaimsOfValid`, and round-trip testing
- Comprehensive test coverage for key rotation scenarios
- Configurable JWT signing algorithm support (HS256, HS384, HS512) via `WithSigningMethod` option
- **RSA algorithm support** (RS256, RS384, RS512, PS256, PS384, PS512)
- **ECDSA algorithm support** (ES256, ES384, ES512)

### Changed
- Renamed all "secret key" terminology to "signing key" for clarity
- Renamed `WithSecretKey` to `WithSigningKey`
- Updated internal field names from `secretKey` to `signingKey`
- Changed `signingKey` type from `[]byte` to `interface{}` to support HMAC, RSA, and ECDSA keys
- Changed `validationKeys` type from `[][]byte` to `[]interface{}` to support multiple key types
