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
| eSignet | `v2.0.0`, `db528423dac7898ad546cb7b2f5f867a949676a7` |
| Thunder | Embedded backend `v0.0.0-20260825062603-12f517c43840` |
| Go | 1.26 |
| Provider selection | `MOSIP_ESIGNET_AUTHN_PROVIDER=breg` |
| Configuration | `REGISTRY_ESIGNET_CONFIG_FILE` points to one YAML file |

This is a source-integrated provider, not a dynamically loaded JAR or Go plugin.
A small adapter and patch are applied to the pinned upstream source during the
build. Upgrading eSignet requires reviewing that patch and rerunning the
composition tests. Existing Java releases remain in Git history and published
artifacts, but their configuration is not accepted here.

## Release image

The version 0.6.1 release distributes the provider as
`ghcr.io/registrystack/esignet-relay-authenticator:0.6.1` for Linux amd64 and arm64.
Use the exact index digest from the release metadata for deployment pins. The
GitHub release includes the OCI archive, checksums, and source metadata.
See [release verification](docs/release.md) before deploying.

The optional [companion OIDC UI](ui/README.md) uses the same pinned eSignet
source and a same-origin proxy for public identity routes. Version 0.5.0 added
the UI as a separate release image and OCI archive. Version 0.6.1 distributes it
as `ghcr.io/registrystack/esignet-oidc-ui:0.6.1`.
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
`esignet-relay-authenticator:0.6.1-candidate`. It does not push images or create a
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

## One-time codes

The production path sends each sign-in code through
[Registry Messaging](docs/esignet-configuration.md#registry-messaging-production),
the Registry Stack product that sends one email or SMS to one recipient from a
reviewed template. The provider looks the person up in BREG, reads their email
address or phone number from the register, generates the code and asks Messaging
to deliver it. The code is single use and expires in minutes. The provider holds
only a salted digest in memory.

Requesting a code never reveals whether a person exists. An unknown or ineligible
person, or one with no contact for the channel, gets the same result as a
successful send, and no message is sent. Resends are limited per person.

Messaging keeps the rendered message and the recipient for its payload retention
period (1 to 30 days, default 7), and its operators can read them. A code that
Messaging holds is single use and expires within minutes, so the exposure is a
live code during its validity. That is the same class of exposure as the email or
SMS provider itself. Choose a short payload retention period if that matters to
your deployment.

Pending codes live in the memory of one provider process. Run one replica, or
use sticky routing, and expect a restart to drop pending codes. A person then
asks for a new one.

The Go `provider.ChallengeVerifier` interface remains the extension seam for an
institution that brings its own sender, through `provider.WithChallengeVerifier`.
The bundled static OTP and local Mailpit verifiers are **synthetic-demo only**,
mutually exclusive with each other and with Messaging, and disabled by default.
Mailpit delivers a generated, transaction-bound one-time code to a fixed
synthetic inbox. A deployment with no verifier configured fails startup.
See [configuration](docs/esignet-configuration.md) for the bounded local flow and
[examples/messaging-otp](examples/messaging-otp) for a Messaging package. This
repository does not implement enrollment, signup, wallet login or identity
assurance.

The adapter supplies structured attributes to eSignet, which applies the
client's UserInfo response mode. There is no provider signing key, certificate
endpoint or custom JWE implementation. Standard subject, issuer and audience
claims remain owned by the OIDC runtime.
