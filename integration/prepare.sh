#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
source "$repo_root/integration/upstream.env"
destination=${1:-"$repo_root/build/esignet"}
archive=${ESIGNET_ARCHIVE:-"$repo_root/build/downloads/$ESIGNET_COMMIT.tar.gz"}
mkdir -p "$(dirname "$archive")" "$(dirname "$destination")"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --silent --show-error "$ESIGNET_ARCHIVE_URL" --output "$archive.partial"
  mv "$archive.partial" "$archive"
fi
if command -v sha256sum >/dev/null; then
  archive_hash=$(sha256sum "$archive" | cut -d ' ' -f 1)
else
  archive_hash=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
fi
[[ "$archive_hash" == "$ESIGNET_ARCHIVE_SHA256" ]] || { echo "Upstream archive checksum mismatch" >&2; exit 1; }

if [[ -e "$destination" ]]; then
  [[ -f "$destination/.esignet-candidate-build" ]] || { echo "Refusing to replace unowned build directory: $destination" >&2; exit 1; }
  rm -rf -- "$destination"
fi
mkdir -p "$destination/upstream" "$destination/provider"
touch "$destination/.esignet-candidate-build"
tar -xzf "$archive" --strip-components=1 -C "$destination/upstream"
service="$destination/upstream/esignet-service"
(cd "$service" && git apply --check "$repo_root/integration/esignet.patch" && git apply "$repo_root/integration/esignet.patch")
cp -R "$repo_root/integration/overlay/." "$service/"
cp "$repo_root/integration/esignet.go.mod" "$service/go.mod"
cp "$repo_root/integration/esignet.go.sum" "$service/go.sum"
cp "$repo_root/go.mod" "$destination/provider/"
if [[ -f "$repo_root/go.sum" ]]; then cp "$repo_root/go.sum" "$destination/provider/"; fi
cp -R "$repo_root/provider" "$destination/provider/"

# Verify the exact dependency before applying the narrowly scoped JWKS fix.
module_metadata=$(go mod download -json "$THUNDER_MODULE@$THUNDER_VERSION")
module_sum=$(printf '%s\n' "$module_metadata" | sed -n 's/^[[:space:]]*"Sum": "\(.*\)",$/\1/p')
[[ "$module_sum" == "$THUNDER_MODULE_SUM" ]] || { echo "Thunder module checksum mismatch" >&2; exit 1; }
# Verify and extract the original zip. Never trust an existing extracted cache.
module_archive="$(go env GOMODCACHE)/cache/download/$THUNDER_MODULE/@v/$THUNDER_VERSION.zip"
mkdir -p "$destination/thunder"
(cd "$repo_root/integration/modulearchive" && go run . "$module_archive" "$THUNDER_MODULE@$THUNDER_VERSION" "$THUNDER_MODULE_SUM" "$destination/thunder")
(cd "$destination/thunder" && git apply --check "$repo_root/integration/thunder.patch" && git apply "$repo_root/integration/thunder.patch")
cp -R "$repo_root/integration/thunder-overlay/internal" "$destination/thunder/"
printf '%s\n' "$service"
