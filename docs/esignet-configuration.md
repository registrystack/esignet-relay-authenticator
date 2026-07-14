# eSignet configuration & deployment

How to wire the **eSignet Relay Authenticator** plugin into an eSignet
deployment: the loader properties, the full configuration reference, signing
keystore setup, required secrets, and packaging for `esignet-with-plugins`.

See the [README](../README.md) for an overview and
[`relay-attribute-release-contract.md`](relay-attribute-release-contract.md) for
the Relay wire contract.

---

## 1. Plugin loading

eSignet discovers authenticator plugins by scanning a base package and selecting
the implementation by bean name:

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService
```

- `scan-base-package` must include `io.registry.esignet.relay` so eSignet
  component-scans the plugin's beans. If you already set this property for other
  plugins, add the package as a comma-separated value.
- `RelayAuthenticationService`, all its collaborator beans, **and the
  `registry.*` properties/validation bean** are gated by
  `@ConditionalOnProperty(mosip.esignet.integration.authenticator=RelayAuthenticationService)`,
  so any other value (or absence) leaves the plugin completely dormant — its
  fail-fast configuration validation does not run and cannot reject an unrelated
  eSignet deployment that never selected this authenticator.

---

## 2. Configuration reference

All plugin properties live under `registry.*`. Defaults below match
`src/main/resources/application.properties`. Secrets are shown as
`${ENV_VAR}` placeholders and must come from the environment or a secret
manager — never hard-coded.

### 2.1 Relay endpoint

| Property | Default | Notes |
|---|---|---|
| `registry.relay.base-url` | *(required)* | Absolute `http(s)` URL of the Relay service. Use `https` in production — a plaintext `http` URL to a non-loopback host logs a startup warning because the Bearer token and subject identifiers would travel unencrypted. |
| `registry.relay.attribute-release.profile-id` | *(required)* | The Relay attribute-release profile id. |
| `registry.relay.attribute-release.profile-version` | *(required)* | The profile version. |
| `registry.relay.attribute-release.path-template` | `/v1/attribute-releases/{profile_id}/versions/{version}/resolve` | Must contain `{profile_id}` and `{version}`. |
| `registry.relay.attribute-release.purpose` | *(required)* | Sent as the `Data-Purpose` request header. Required and validated fail-fast: the governed profile rejects a request with no purpose (`auth.purpose_required`), so a blank value is refused at startup rather than silently dropping the header. |
| `registry.relay.attribute-release.accept` | `application/json` | Response media type. |
| `registry.relay.subject.id-type` | `national_id` | The `subject.id_type` sent to Relay (identifier-echo profile). |
| `registry.relay.default-claims` | *(optional)* | Profile-declared claim list used to filter exchange requests to the profile. |
| `registry.relay.connect-timeout-ms` | `2000` | HTTP connect timeout. |
| `registry.relay.read-timeout-ms` | `5000` | HTTP read timeout. |

### 2.2 Relay authorization (always `Authorization: Bearer`)

| Property | Default | Notes |
|---|---|---|
| `registry.relay.auth.bearer-token-file` | `${REGISTRY_RELAY_AUTH_BEARER_TOKEN_FILE}` *(required)* | Absolute path to the mounted bearer credential file. Sent as `Authorization: Bearer <token>`. There is no `X-API-Key` path. |

The plugin reopens this file immediately before every Relay request, so an
atomic file replacement rotates the credential without restarting eSignet. It
does not cache token content. The path must identify a regular file no larger
than 16 KiB. File content must be one valid RFC 6750 bearer token encoded as
UTF-8, with an optional single trailing LF or CRLF. Empty, malformed,
oversized, missing, and unreadable files fail closed before any HTTP request.
Errors and logs disclose neither the configured path nor token content.

### 2.3 Authentication challenge

| Property | Default | Notes |
|---|---|---|
| `registry.esignet.auth.supported-factors` | `OTP` | Supported auth factors. |
| `registry.esignet.auth.otp.channels` | `email,phone` | OTP channels reported by `isSupportedOtpChannel`. |
| `registry.esignet.auth.otp.mode` | `static` | The bundled verifier mode. |
| `registry.esignet.auth.otp.static-value` | `${REGISTRY_ESIGNET_STATIC_OTP:111111}` | Demo-only fixed OTP. |
| `registry.esignet.auth.otp.static-enabled` | `false` | **Keep `false` in production.** No default production static OTP. |

> The static OTP verifier is a local/demo convenience. Provide a real
> `ChallengeVerifier` bean for production; it overrides the static one via
> `@ConditionalOnMissingBean`.

### 2.4 Internal KYC token & PSUT (secrets)

| Property | Default | Notes |
|---|---|---|
| `registry.esignet.kyc-token.hmac-secret` | `${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}` | HS256 key for the short-lived internal KYC token. **Must be ≥ 32 characters** (validation fails otherwise); use a high-entropy random value. |
| `registry.esignet.kyc-token.ttl-seconds` | `300` | KYC token TTL. Keep short (replay mitigation). |
| `registry.esignet.psut.hmac-secret` | `${REGISTRY_ESIGNET_PSUT_SECRET}` | HMAC key for PSUT derivation. **Must differ** from the KYC token secret (enforced fail-fast at startup) and be **≥ 32 characters**. |

### 2.5 KYC/UserInfo signing (keystore)

| Property | Default | Notes |
|---|---|---|
| `registry.esignet.kyc.response-mode` | `self-contained-jws` | Signing-required mode (RS256 JWS). |
| `registry.esignet.kyc.signing.keystore-path` | `${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}` | Path to the RSA signing keystore. |
| `registry.esignet.kyc.signing.keystore-type` | `PKCS12` | `PKCS12` or `JKS`. |
| `registry.esignet.kyc.signing.keystore-password` | `${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}` | Keystore password. |
| `registry.esignet.kyc.signing.key-alias` | `${REGISTRY_ESIGNET_KYC_KEY_ALIAS}` | Signing key alias. |
| `registry.esignet.kyc.signing.key-password` | `${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}` | Signing key password. |
| `registry.esignet.kyc.signing.algorithm` | `RS256` | JWS algorithm. |

### 2.6 Claim mapping

Maps Relay-released claims (and the plugin-derived PSUT) into eSignet/OIDC
UserInfo claims. `$psut` marks a protocol-derived claim supplied locally and
**never** requested from Relay. Dotted OIDC claim names bind via
`claim-map[<dotted.name>]`. When unset, the default map below applies.

```properties
registry.esignet.claim-map.sub=$psut
registry.esignet.claim-map.individual_id=individual_id
registry.esignet.claim-map.name=name
registry.esignet.claim-map.given_name=given_name
registry.esignet.claim-map.family_name=family_name
registry.esignet.claim-map.birthdate=birthdate
registry.esignet.claim-map.gender=gender
registry.esignet.claim-map[address.region]=address.region
```

### 2.7 Account-check claims

| Property | Default | Notes |
|---|---|---|
| `registry.esignet.account-check-claims` | `individual_id` | Minimal claim list for the `doKycAuth` account-check probe. Keep this free of demographics so nothing is released before consent. |

---

## 3. Generating a signing keystore

The plugin signs with an RSA key from a standard keystore (no committed keys).
The key must be **at least 2048 bits** — a smaller key is rejected when the
signing material is loaded. Generate one for a deployment with `keytool`:

```bash
keytool -genkeypair \
  -alias esignet-relay-kyc \
  -keyalg RSA -keysize 2048 \
  -dname "CN=esignet-relay-authenticator" \
  -validity 825 \
  -storetype PKCS12 \
  -keystore kyc-signing.p12 \
  -storepass "$REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD" \
  -keypass  "$REGISTRY_ESIGNET_KYC_KEY_PASSWORD"
```

Then point the plugin at it:

```properties
registry.esignet.kyc.signing.keystore-path=/run/secrets/kyc-signing.p12
registry.esignet.kyc.signing.keystore-type=PKCS12
registry.esignet.kyc.signing.key-alias=esignet-relay-kyc
```

The `kid` published by `getAllKycSigningCertificates` is derived deterministically
from the public key, so re-deploying with the same key yields the same `kid`.

> Store the keystore and its passwords in your platform secret manager / mounted
> secret, not in the application config or the image.

---

## 4. Required secrets (summary)

| Env var | Backs |
|---|---|
| `REGISTRY_RELAY_AUTH_BEARER_TOKEN_FILE` | `registry.relay.auth.bearer-token-file` |
| `REGISTRY_ESIGNET_KYC_TOKEN_SECRET` | `registry.esignet.kyc-token.hmac-secret` |
| `REGISTRY_ESIGNET_PSUT_SECRET` | `registry.esignet.psut.hmac-secret` |
| `REGISTRY_ESIGNET_KYC_KEYSTORE_PATH` | keystore location |
| `REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD` | keystore password |
| `REGISTRY_ESIGNET_KYC_KEY_ALIAS` | signing key alias |
| `REGISTRY_ESIGNET_KYC_KEY_PASSWORD` | signing key password |

Config validation fails fast (at startup) on missing required values and redacts
all secrets in any `toString`/log output.

---

## 5. Packaging for `esignet-with-plugins`

eSignet's plugin-enabled distribution (`esignet-with-plugins`) loads plugin JARs
from a plugins directory on the classpath / loader path.

1. Obtain the plugin JAR — either download a released asset (preferred, pinned):

   ```bash
   VERSION=0.1.0
   curl -fsSL -o esignet-relay-authenticator-${VERSION}.jar \
     https://github.com/jeremi/esignet-relay-authenticator/releases/download/v${VERSION}/esignet-relay-authenticator-${VERSION}.jar
   ```

   …or build it from source:

   ```bash
   mvn -DskipTests package
   # → target/esignet-relay-authenticator-<version>.jar
   ```

   Releases are cut by tagging `v*`, which publishes the JAR via
   `.github/workflows/release.yml`.

2. Place the JAR in the eSignet plugins directory used by your deployment
   (e.g. the `loader_path` / `${mosip.esignet.integration.plugin-dir}` mounted
   into the `esignet-with-plugins` image), alongside any other authenticator
   plugins.

3. Provide the loader + plugin properties (sections 1–2) through the eSignet
   configuration source (config-server, mounted `application.properties`, or
   environment), and mount the signing keystore + secrets.

4. Restart eSignet. On startup the bean logs confirm the plugin is active and
   the signing key loaded (the log shows only the non-sensitive `kid` and
   algorithm — never key material).

The plugin depends on eSignet to provide the integration API, Spring, and
Jackson at runtime (all `provided` scope), so the JAR stays small and shares the
runtime's library versions.

---

## 6. Verifying the deployment

- The authenticator bean is present only when
  `mosip.esignet.integration.authenticator=RelayAuthenticationService`.
- `GET` the eSignet KYC signing certificates endpoint and confirm a certificate
  with the plugin's `kid` is published.
- A first authentication should call the Relay attribute-release endpoint
  (visible in Relay access logs as `POST .../resolve`), not a row-read API.
- An end-to-end smoke test against a running eSignet + live Relay
  (for example, via Solmara Lab) is **not** part of this repository's test suite
  and remains a deployment-time follow-up. See
  [`solmara-lab-deployment.md`](solmara-lab-deployment.md) for the deployment
  checklist.
