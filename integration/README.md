# Pinned eSignet host integration

`prepare.sh` verifies the upstream archive checksum, applies `esignet.patch`, and
copies the Go adapter into the pinned host. Generated source stays under `build/`.
The nested overlay module only prevents the standalone core's tests from treating
unassembled host files as its own packages.

The pinned Thunder Go module is verified against its recorded module checksum.
The build verifies the Go h1 checksum directly over the archive entries, then
extracts them into the generated build and applies `thunder.patch`. Existing
extracted module caches are never copied. That patch
backports the RSA algorithm correction from
[Thunder c0ba0579](https://github.com/thunder-id/thunderid/commit/c0ba0579b4bcb1d23be77242d7ab84eeb246128e),
adapted to the pinned API: RSA JWK metadata follows the provider's supported
signing algorithm instead of always advertising RS256. Existing key identifiers
and token signatures remain unchanged. The regression selects the published key
by algorithm and verifies actual RSA JWT signatures; incompatible algorithm
metadata is rejected.

The patch registers the BREG authentication provider and applies fresh consent to
BREG sign-ins. It also adds exactly two names to the host's static client claim
allowlist: standard OIDC `family_name` and institution business claim
`person_reference`. The latter supports institution applications that require an
explicitly requested and consented business identifier. It does not replace the
pairwise OIDC `sub`. Registration still rejects arbitrary claim names; configuring
either added claim does not release its value without the provider mapping and
the user's consent.

The BREG consent wrapper translates the host's essential-refusal error into the
pinned engine's recognized error code, stopping the flow without code issuance.
It delegates decisions to the host and requests a fresh prompt on each login.
The bundled demo flow advertises only `mosip:idp:acr:static-code`, matching the
explicit demo verifier. A production verifier requires a reviewed flow matching
its actual assurance; the demo does not advertise generated-code or password.

The host access-log patch records URL paths and omits Referer values, so OAuth
query parameters and callback codes do not enter access logs. Request handling
still receives the original URL and headers.
Runtime-store debug messages retain namespace diagnostics without logging record
keys or values.

`test.sh` tests the assembled client validation, adapter, executor, engine, and
host entrypoint, and builds the host binary. `build.sh` exports both Linux amd64
and arm64 variants to `dist/esignet-breg-candidate.oci.tar`, with SBOM and provenance
attestations. It never pushes an image. The Dockerfile retains the original
upstream license and third-party notices under `/licenses/esignet`.

For a native local image, run `./integration/build.sh --load`. This loads
`esignet-relay-authenticator:0.3.0-candidate` into the current Linux Docker daemon
without changing any running service. Use `--help` for the two output modes.

The build wrapper uses Python 3 to compute a deterministic SHA-256 over the
Dockerfile, Docker ignore rules, both root module files, and the complete
`provider/` and `integration/` trees. Paths, executable bits, symlink targets,
and file contents contribute to the digest; timestamps and `build/`, `dist/`,
and Git internals do not. OCI labels record that digest, the base Git revision,
whether those inputs are dirty, and the exact upstream compatibility revision.
Direct Docker builds that omit the wrapper's arguments explicitly label their
source state as unrecorded.

After the multiarchitecture export, the build script verifies the image index,
both platform manifests, and their source labels. It writes an archive `.sha256`
sidecar and `.metadata.json` containing the archive checksum, image digests,
attestation digests, and source labels next to the OCI archive.
