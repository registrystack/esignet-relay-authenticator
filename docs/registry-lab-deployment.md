# Deploying the plugin into registry-lab

How to run the **eSignet Relay Authenticator** plugin inside the
[`registry-lab`](https://github.com/jeremi/registry-lab) stack against a live
Relay, for end-to-end smoke testing.

This repo produces a **thin authenticator JAR** that eSignet side-loads; it is
not a service and has no image of its own. The lab orchestration (compose files
/ manifests, the eSignet service, and the Relay) lives in `registry-lab`. This
guide is the **plugin-side checklist** — what the lab must mount, configure, and
provision. Apply the actual compose/manifest edits in `registry-lab`.

See [`esignet-configuration.md`](esignet-configuration.md) for the full property
reference and keystore setup, and
[`relay-attribute-release-contract.md`](relay-attribute-release-contract.md) for
the Relay wire contract.

---

## Prerequisites in the lab

- **eSignet runs the `esignet-with-plugins` distribution** (the plugin-loading
  build), with a plugins directory on its `loader_path` /
  `${mosip.esignet.integration.plugin-dir}`. Vanilla eSignet will not load the
  plugin.
- **A reachable Relay** with the attribute-release route published (see the
  Relay prerequisites section below).
- A way to inject config and secrets into the eSignet container (config-server,
  mounted `application.properties`, or environment + secret mounts).

---

## 1. Get the plugin JAR

**Preferred — a released artifact.** Tagging this repo (`v*`) publishes a pinned
JAR as a GitHub Release asset (see `.github/workflows/release.yml`). The lab can
download it deterministically:

```bash
VERSION=0.1.0   # the released tag, without the leading 'v'
curl -fsSL -o esignet-relay-authenticator-${VERSION}.jar \
  https://github.com/jeremi/esignet-relay-authenticator/releases/download/v${VERSION}/esignet-relay-authenticator-${VERSION}.jar
```

**Alternative — build from source** (until a version is tagged; the default
build is `0.1.0-SNAPSHOT`):

```bash
mvn -DskipTests package
# -> target/esignet-relay-authenticator-<version>.jar
```

> Pin a released version in the lab rather than tracking a branch or `-SNAPSHOT`,
> so lab runs are reproducible.

## 2. Mount the JAR into eSignet

Place the JAR in the eSignet plugins directory used by the lab's
`esignet-with-plugins` service. In a compose stack this is typically a bind
mount or volume into the loader path, e.g.:

```yaml
# registry-lab: esignet service (illustrative — match the lab's actual paths)
services:
  esignet:
    image: <esignet-with-plugins image>
    volumes:
      - ./plugins/esignet-relay-authenticator-0.1.0.jar:/home/mosip/plugins/esignet-relay-authenticator-0.1.0.jar:ro
    environment:
      # see step 3
```

The exact loader path and mount convention are defined by the lab's eSignet
image — align with what `registry-lab` already uses for plugin JARs.

## 3. Configuration

Provide the loader selector plus the `registry.*` block, pointed at the lab's
Relay. Minimal set (full reference in `esignet-configuration.md` §1–2):

```properties
# Plugin loading
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService

# Relay endpoint (point at the lab's Relay service)
registry.relay.base-url=http://relay:8080
registry.relay.attribute-release.profile-id=<lab profile id>
registry.relay.attribute-release.profile-version=v1
registry.relay.attribute-release.purpose=<lab purpose URI>
registry.relay.subject.id-type=national_id

# Relay authorization — always Authorization: Bearer
registry.relay.auth.bearer-token=${REGISTRY_RELAY_TOKEN}
```

> Use `https` for `base-url` to anything other than a loopback host: a plaintext
> `http` URL logs a startup warning because the Bearer token and subject
> identifiers would travel unencrypted. In-cluster (`http://relay:8080`) is
> acceptable for the lab; secure it for anything internet-routable.

## 4. Secrets (lab secret store / env)

Inject these as the lab's secret mounts or environment — never commit them
(`esignet-configuration.md` §4):

| Env var | Backs |
|---|---|
| `REGISTRY_RELAY_TOKEN` | Relay bearer credential (with the release scope) |
| `REGISTRY_ESIGNET_KYC_TOKEN_SECRET` | internal KYC token HMAC (≥ 32 chars) |
| `REGISTRY_ESIGNET_PSUT_SECRET` | PSUT HMAC (≥ 32 chars, **distinct** from above) |
| `REGISTRY_ESIGNET_KYC_KEYSTORE_PATH` | RSA signing keystore location (mounted) |
| `REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD` | keystore password |
| `REGISTRY_ESIGNET_KYC_KEY_ALIAS` | signing key alias |
| `REGISTRY_ESIGNET_KYC_KEY_PASSWORD` | signing key password |

Generate the signing keystore (RSA ≥ 2048-bit) per `esignet-configuration.md` §3
and mount it read-only. Config validation fails fast at startup on any missing
required value.

## 5. Relay-side prerequisites (in the lab)

The lab's Relay must be set up so the governed release call succeeds:

- The attribute-release **profile is published** at the pinned
  `{profile_id}/{version}`.
- The bearer token is **provisioned with the release scope**
  (e.g. `civil_registry:identity_release`).
- The configured **purpose is allow-listed** for that profile.
- The Relay build includes **registry-relay PR #162** so it emits
  `release.subject_invalid` and honors `include_source_metadata` as documented.
  Older Relay builds still work — the plugin aliases the legacy `filter.*` codes
  to `subject_invalid` for the rollout window (see
  `relay-attribute-release-contract.md`).

## 6. Bring up and verify

After the JAR is mounted, config + secrets are in place, and the keystore is
mounted, (re)start the eSignet service. Then verify (`esignet-configuration.md`
§6):

- Startup logs confirm the plugin bean is active and the signing key loaded
  (only the non-sensitive `kid` and algorithm are logged — never key material).
- The eSignet KYC signing-certificates endpoint publishes a cert with the
  plugin's `kid`.
- A first authentication shows a `POST .../resolve` in the Relay access log
  (the governed release call), not a row-read API.

---

## Sequencing checklist

1. Merge the plugin PR and **tag a release** (`v*`) so the lab pulls a pinned JAR.
2. Deploy a Relay build that includes **registry-relay #162** to the lab.
3. Publish the profile, provision the token + scope, and allow-list the purpose.
4. Mount the JAR, apply config + secrets, mount the keystore, restart eSignet.
5. Run the verification steps above.
