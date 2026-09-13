#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
usage() {
  cat <<'EOF'
Usage: integration/build.sh [--ui] [--load | --help]

Default: export Linux amd64 and arm64 images, SBOM, and provenance to
         dist/esignet-breg-candidate.oci.tar.
--ui:    select the companion OIDC UI Dockerfile and esignet-ui-candidate archive.
--load:  build and load the Docker daemon's native Linux architecture as
         the selected image candidate tag (override with CANDIDATE_IMAGE).
--help:  show this help.

Both export modes use the selected pinned Dockerfile and verified upstream source.
Neither mode pushes images or starts, stops, or replaces running services.
EOF
}
ui=false
load=false
for option in "$@"; do
  case "$option" in
    --help|-h) usage; exit 0 ;;
    --ui) [[ "$ui" == false ]] || { usage >&2; exit 2; }; ui=true ;;
    --load) [[ "$load" == false ]] || { usage >&2; exit 2; }; load=true ;;
    *) usage >&2; exit 2 ;;
  esac
done
source_args=("$repo_root")
dockerfile="$repo_root/Dockerfile"
archive="$repo_root/dist/esignet-breg-candidate.oci.tar"
candidate_image=${CANDIDATE_IMAGE:-esignet-relay-authenticator:0.5.0-candidate}
if [[ "$ui" == true ]]; then
  source_args+=(--ui)
  dockerfile="$repo_root/ui/Dockerfile"
  archive="$repo_root/dist/esignet-ui-candidate.oci.tar"
  candidate_image=${CANDIDATE_IMAGE:-esignet-oidc-ui:0.5.0-candidate}
fi
if [[ "$load" == true ]]; then
  [[ "$(docker info --format '{{.OSType}}')" == linux ]] || { echo "A Linux Docker daemon is required" >&2; exit 1; }
  case "$(docker info --format '{{.Architecture}}')" in
    arm64|aarch64) architecture=arm64 ;;
    amd64|x86_64) architecture=amd64 ;;
    *) echo "Supported local architectures: amd64 and arm64" >&2; exit 1 ;;
  esac
fi
read -r source_sha source_revision source_state <<<"$(python3 "$repo_root/integration/source-metadata.py" "${source_args[@]}")"
[[ "$source_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "Could not determine candidate source digest" >&2; exit 1; }
metadata_args=(--build-arg "CANDIDATE_SOURCE_SHA256=$source_sha" \
  --build-arg "CANDIDATE_SOURCE_REVISION=$source_revision" --build-arg "CANDIDATE_SOURCE_STATE=$source_state")
if [[ "$ui" == true ]]; then
  source "$repo_root/integration/upstream.env"
  metadata_args+=(--build-arg "ESIGNET_COMMIT=$ESIGNET_COMMIT"
    --build-arg "ESIGNET_ARCHIVE_URL=$ESIGNET_ARCHIVE_URL"
    --build-arg "ESIGNET_ARCHIVE_SHA256=$ESIGNET_ARCHIVE_SHA256"
    --build-arg "CANDIDATE_VERSION=0.5.0")
fi
verify_source_unchanged() {
  local current_sha unused_revision unused_state
  read -r current_sha unused_revision unused_state <<<"$(python3 "$repo_root/integration/source-metadata.py" "${source_args[@]}")"
  [[ "$current_sha" == "$source_sha" ]] || { echo "Source inputs changed during the build; rebuild before using the candidate" >&2; exit 1; }
}
if [[ "$load" == true ]]; then
  docker buildx build --file "$dockerfile" --platform "linux/$architecture" --load "${metadata_args[@]}" \
    --tag "$candidate_image" "$repo_root"
  verify_source_unchanged
  exit 0
fi
mkdir -p "$repo_root/dist"
docker buildx build --file "$dockerfile" --platform linux/amd64,linux/arm64 --provenance=mode=max \
  "${metadata_args[@]}" \
  --sbom=true --output "type=oci,dest=$archive" \
  --tag "$candidate_image" "$repo_root"
verify_source_unchanged
python3 "$repo_root/integration/artifact-metadata.py" "$archive" "$source_sha"
