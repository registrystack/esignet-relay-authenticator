#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
source "$repo_root/integration/upstream.env"
audit_directory=$(mktemp -d)
trap 'rm -rf "$audit_directory"' EXIT
docker buildx build --file "$repo_root/ui/Dockerfile" --target ui-build --load \
  --build-arg "ESIGNET_ARCHIVE_URL=$ESIGNET_ARCHIVE_URL" \
  --build-arg "ESIGNET_ARCHIVE_SHA256=$ESIGNET_ARCHIVE_SHA256" \
  --iidfile "$audit_directory/image-id" "$repo_root"
docker run --rm --read-only --tmpfs /tmp \
  -e npm_config_cache=/tmp/npm-cache "$(cat "$audit_directory/image-id")" \
  npm audit --omit=dev --package-lock-only --audit-level=high
