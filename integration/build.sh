#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
candidate_image=${CANDIDATE_IMAGE:-esignet-relay-authenticator:0.3.0-candidate}
usage() {
  cat <<'EOF'
Usage: integration/build.sh [--load | --help]

Default: export Linux amd64 and arm64 images, SBOM, and provenance to
         dist/esignet-breg-candidate.oci.tar.
--load:  build and load the Docker daemon's native Linux architecture as
         esignet-relay-authenticator:0.3.0-candidate for an isolated local demo.
--help:  show this help.

Both modes use the same pinned Dockerfile and verified upstream source.
Neither mode pushes images or starts, stops, or replaces running services.
EOF
}
if [[ $# -gt 1 ]]; then usage >&2; exit 2; fi
case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --load)
    [[ "$(docker info --format '{{.OSType}}')" == linux ]] || { echo "A Linux Docker daemon is required" >&2; exit 1; }
    case "$(docker info --format '{{.Architecture}}')" in
      arm64|aarch64) architecture=arm64 ;;
      amd64|x86_64) architecture=amd64 ;;
      *) echo "Supported local architectures: amd64 and arm64" >&2; exit 1 ;;
    esac
    ;;
  "") ;;
  *) usage >&2; exit 2 ;;
esac
read -r source_sha source_revision source_state <<<"$(python3 "$repo_root/integration/source-metadata.py" "$repo_root")"
[[ "$source_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "Could not determine candidate source digest" >&2; exit 1; }
metadata_args=(--build-arg "CANDIDATE_SOURCE_SHA256=$source_sha" \
  --build-arg "CANDIDATE_SOURCE_REVISION=$source_revision" --build-arg "CANDIDATE_SOURCE_STATE=$source_state")
verify_source_unchanged() {
  local current_sha unused_revision unused_state
  read -r current_sha unused_revision unused_state <<<"$(python3 "$repo_root/integration/source-metadata.py" "$repo_root")"
  [[ "$current_sha" == "$source_sha" ]] || { echo "Source inputs changed during the build; rebuild before using the candidate" >&2; exit 1; }
}
if [[ "${1:-}" == --load ]]; then
  docker buildx build --platform "linux/$architecture" --load "${metadata_args[@]}" \
    --tag "$candidate_image" "$repo_root"
  verify_source_unchanged
  exit 0
fi
mkdir -p "$repo_root/dist"
docker buildx build --platform linux/amd64,linux/arm64 --provenance=mode=max \
  "${metadata_args[@]}" \
  --sbom=true --output "type=oci,dest=$repo_root/dist/esignet-breg-candidate.oci.tar" \
  --tag "$candidate_image" "$repo_root"
verify_source_unchanged
python3 "$repo_root/integration/artifact-metadata.py" "$repo_root/dist/esignet-breg-candidate.oci.tar" "$source_sha"
