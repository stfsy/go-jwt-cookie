#!/bin/bash

set -euo pipefail

go vet ./...

# if GITHUB_ACTIONS is set then we are running in CI
if [[ "${GITHUB_ACTIONS:-}" != "" ]]; then
    go test -cover -race -timeout 5s ./...
else
    go test -cover -timeout 5s ./...
fi