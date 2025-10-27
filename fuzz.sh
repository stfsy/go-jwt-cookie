#!/bin/bash

set -euo pipefail

# Run fuzz tests for SetJWTCookie
go test -fuzz=FuzzSetJWTCookie -fuzztime=120s

# Run fuzz tests for GetClaimsOfValid
go test -fuzz=FuzzGetClaimsOfValid -fuzztime=120s

# Run fuzz tests for round trip
go test -fuzz=FuzzRoundTrip -fuzztime=120s

# Run with race detector for shorter time
go test -fuzz=FuzzSetJWTCookie -race -fuzztime=20s
go test -fuzz=FuzzGetClaimsOfValid -race -fuzztime=20s
go test -fuzz=FuzzRoundTrip -race -fuzztime=20s