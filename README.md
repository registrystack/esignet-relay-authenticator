# eSignet BREG provider

A native Go authentication provider for eSignet 2.0, backed by a governed
Base Registry Engine lookup. Version **0.3.0** replaces the unused Java
integration. The repository name remains `esignet-relay-authenticator`;
the current provider supports **BREG only**. Relay integration is deferred.

The provider verifies a deployment-supplied challenge, checks an account through
BREG, and retrieves approved identity fields after fresh consent. BREG remains
the system of record and independently enforces its access profile. A configured
OAuth token issuer authenticates the workload. eSignet owns OAuth/OIDC,
encrypted flow state, and UserInfo signing and encryption.

## Compatibility

| Component | Pin |
| --- | --- |
| eSignet | `v2.0.0-beta.1`, `df0d0e771dae16eb2597b8e5b5dc65e70baa7f86` |
| Thunder | The replacement module pinned by that release, `9a568aec1cbf` |
| Go | 1.26 |
| Provider selection | `MOSIP_ESIGNET_AUTHN_PROVIDER=breg` |
| Configuration | `REGISTRY_ESIGNET_CONFIG_FILE` points to one YAML file |

This is a source-integrated provider, not a dynamically loaded JAR or Go plugin.
A small adapter and patch are applied to the pinned upstream source during the
build. Upgrading eSignet requires reviewing that patch and rerunning the
composition tests. Existing Java releases remain in Git history and published
artifacts, but their configuration is not accepted here.

## Release image

The release workflow publishes version 0.5.0 as
`ghcr.io/registrystack/esignet-relay-authenticator:0.5.0` for Linux amd64 and arm64.
Use the exact index digest from the release metadata for deployment pins. The
GitHub release also includes the OCI archive, checksums, and source metadata.
See [release verification](docs/release.md) before deploying.

The optional [companion OIDC UI](ui/README.md) uses the same pinned eSignet
source and a same-origin proxy for public identity routes. Version 0.5.0 adds
`ghcr.io/registrystack/esignet-oidc-ui:0.5.0` as a separate image and OCI archive.
Both components share the release's source revision; pin each by its own digest.

## Build and check

```sh
GOTOOLCHAIN=go1.26.8 go test -race ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
./integration/test.sh
./integration/build.sh
# For a local Docker demo:
./integration/build.sh --load
```

Core tests use HTTP fixtures. Integration checks compile the adapter against
pinned eSignet and Thunder source. The image builder writes both Linux amd64 and
arm64 variants to `dist/esignet-breg-candidate.oci.tar`, tagged
`esignet-relay-authenticator:0.5.0-candidate`. It does not push images or create a
release. Inspect `integration/upstream.env` for exact source and image pins.

See [configuration](docs/esignet-configuration.md), the
[BREG wire contract](docs/breg-lookup-contract.md), and the
[Solmara journey](docs/solmara-lab-deployment.md).

## Authentication and privacy

- A failed challenge makes no token-issuer or BREG request. Account checks request only
  their configured nonempty field set.
- Every login asks for fresh consent. Attribute retrieval intersects approved
  claim names with the claim map and provisioned BREG fields. An empty result
  makes no lookup and never selects a default projection.
- The selector travels in the request body. Only `data.domainData` becomes
  identity claims; Registry Record metadata is not a claim source.
- A versioned JSON tuple and an independent HMAC key produce a stable
  RP/client-specific subject. The raw identifier is never OIDC `sub`.
- A five-minute JSON-safe context binds the lookup to RP, client, transaction,
  subject and identifier type. eSignet encrypts flow storage; there is no extra
  signed KYC bearer token or provider-side identity cache.
- Token client authentication uses ES256 or RS256 `private_key_jwt` with an
  explicit assertion audience, resource and scope set. Cache misses are
  synchronized; validity includes acquisition time. Rejected credentials are
  invalidated without replaying the failed lookup.
- Errors are fixed and value-free. HTTP calls have bounded duration and response
  size and do not follow redirects.

The Go `provider.ChallengeVerifier` interface is the production extension seam.
The bundled static OTP and local Mailpit verifiers are **synthetic-demo only**,
mutually exclusive and disabled by default. Mailpit delivers a generated,
transaction-bound one-time code to a fixed synthetic inbox. A deployment without
a configured verifier fails startup. See [configuration](docs/esignet-configuration.md)
for the bounded local flow. This repository does not implement production OTP
delivery, enrollment, signup, wallet login or identity assurance.

The adapter supplies structured attributes to eSignet, which applies the
client's UserInfo response mode. There is no provider signing key, certificate
endpoint or custom JWE implementation. Standard subject, issuer and audience
claims remain owned by the OIDC runtime.
