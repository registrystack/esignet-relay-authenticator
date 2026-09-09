#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
service=$("$repo_root/integration/prepare.sh")
cd "$service"
go mod verify
go test -mod=readonly -race ./internal/httpmiddleware ./internal/clientmgmt ./internal/engine/breg ./internal/engine/executors ./internal/engine/runtimestores/... ./internal/engine ./cmd/esignet
CGO_ENABLED=0 go build -mod=readonly -trimpath -o "$repo_root/build/esignet-candidate" ./cmd/esignet
