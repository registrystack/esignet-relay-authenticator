# Release v0.4.0

The manually dispatched **Release v0.4.0** workflow publishes the native Go BREG provider to `ghcr.io/registrystack/esignet-relay-authenticator:0.4.0` and creates the GitHub release and source tag `v0.4.0`. It does not publish a `latest` image tag or change a deployment.

Merge the release changes into `main` and wait for the **CI** push run on that exact commit to succeed. Then dispatch the workflow from `main`:

```sh
gh workflow run release.yml --repo registrystack/esignet-relay-authenticator --ref main
gh run list --repo registrystack/esignet-relay-authenticator --workflow release.yml
```

The workflow requires the canonical repository, current main HEAD, successful exact-commit CI, and unused Git tag, GitHub release, and image version. Repository ruleset changes are not required. The workflow token needs contents, packages, attestations, and identity-token write permissions and Actions read permission. If the organization restricts those permissions, configure them before dispatching.

The release runs core race tests and static checks, the pinned host integration tests and build, and `govulncheck` v1.1.4 with Go 1.26.8 against the core and assembled runtime entrypoint. Reachable vulnerability findings block publication. Module-only findings remain visible in scanner output for review.

The workflow builds one OCI archive containing Linux amd64 and arm64 images, SBOMs, and BuildKit provenance. It checks source labels, clean revision, the archive checksum, and every OCI blob digest. A native image imported from that archive must start and reject a deliberately invalid configuration before connecting to any services. This is a bounded first-run smoke check; it does not claim that a complete institutional deployment has been configured or tested.

GitHub authenticates an artifact attestation over the archive and its checksum and metadata sidecars. The workflow retains these exact bytes as a run artifact before publication. `skopeo copy --all --preserve-digests` publishes that archive, including its platform and attestation manifests, and the workflow verifies the registry index digest before creating the source tag and release. It never rebuilds during promotion.

## Verify published artifacts

Download the four release assets into an empty directory:

```sh
gh release download v0.4.0 --repo registrystack/esignet-relay-authenticator
sha256sum --check esignet-breg-candidate.oci.tar.sha256
for artifact in esignet-breg-candidate.oci.tar esignet-breg-candidate.oci.tar.metadata.json; do
  gh attestation verify "$artifact" \
    --repo registrystack/esignet-relay-authenticator \
    --signer-workflow registrystack/esignet-relay-authenticator/.github/workflows/release.yml \
    --source-ref refs/heads/main \
    --bundle attestation.intoto.jsonl
done
```

The historical `candidate` filename is retained as the build export name. The image version label and source revision in `esignet-breg-candidate.oci.tar.metadata.json` identify the released version. Use its `image_index_digest` to pin a deployment or compare the registry identity:

```sh
skopeo inspect --raw docker://ghcr.io/registrystack/esignet-relay-authenticator:0.4.0 > published-index.json
printf 'sha256:'; sha256sum published-index.json
```

The computed digest must match `image_index_digest`. Verify the release tag resolves to the metadata's `org.opencontainers.image.revision` and that `io.registry.source.state` is `clean`. The attestation verification output must identify the release workflow and that same source commit. The release includes an attestation bundle so verification does not depend on keeping the temporary workflow artifact.

Check unauthenticated image access if the release is intended for public use. A newly created GHCR package can require a separate package-visibility setting even when its source repository is public. The workflow does not change organization or package visibility settings.

## Interrupted publication

An existing version causes a new run to fail, including after a partially completed release. Do not delete or move the tag, overwrite an image, replace an uploaded asset, or rebuild the same version to bypass this check.

Inspect the original run, its retained archive and attestation, the Git tag target, any draft release, and the published image digest. Resume only missing publication steps using the original verified bytes when every existing identity and checksum agrees with the original source and metadata. A matching draft can be completed by uploading only missing assets and publishing it. Do not use `--clobber`. If the image exists but the tag does not, first verify its exact index digest against the retained metadata before creating the tag at the original source commit.

If any published identity or bytes differ, fix forward under a new version. If the original artifact cannot be recovered and verified, do not manufacture replacement bytes for v0.4.0. The run artifact is retained for 30 days; published release assets and the authenticated bundle are the durable distribution record.
