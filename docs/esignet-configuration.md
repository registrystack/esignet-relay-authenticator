# eSignet configuration

## Plugin loading

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService
```

All plugin beans and fail-fast validation are conditional on that authenticator selection.

## Relay V2

| Property | Default | Requirement |
|---|---:|---|
| `registry.relay.base-url` | required | Absolute HTTP(S) Relay service URL. Use HTTPS outside loopback. |
| `registry.relay.resource` | required | Compiled Registry resource identifier. |
| `registry.relay.lookup` | required | Lookup identifier whose selector is `uin`. |
| `registry.relay.access-profile` | unset | Explicit compiled access profile. Omit only when the operation default is intended. |
| `registry.relay.accept` | `application/json` | Relay response media type. |
| `registry.relay.default-claims` | required | Closed list of provisioned/selectable Relay properties. |
| `registry.relay.connect-timeout-ms` | `2000` | Positive connection timeout. |
| `registry.relay.read-timeout-ms` | `5000` | Positive request timeout. |

The plugin owns the fixed route and request shape. There is no configurable V1 path template,
profile version, `Data-Purpose`, static bearer token, credential-kind label, or client secret.

## Registry Mint

| Property | Default | Requirement |
|---|---:|---|
| `registry.mint.token-endpoint` | required | Absolute Mint token endpoint and exact JWT assertion audience. |
| `registry.mint.client-id` | required | Registered Mint client. Used for both `iss` and `sub`. |
| `registry.mint.private-jwk` | required | Secret-provided private RSA JWK described below. |
| `registry.mint.assertion-lifetime-seconds` | `120` | 1 through 300 seconds. |
| `registry.mint.token-cache-max-seconds` | `300` | 1 through 3600 seconds, further bounded by Mint `expires_in`. |
| `registry.mint.connect-timeout-ms` | `2000` | Positive connection timeout. |
| `registry.mint.read-timeout-ms` | `5000` | Positive request timeout. |

The private JWK must have `kty=RSA`, `alg=RS256`, a non-empty `kid`, an RSA modulus of at least 2048
bits, and private CRT members `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, and `qi`. Store the compact JSON in
a secret manager, for example:

```properties
registry.mint.private-jwk=${REGISTRY_MINT_CLIENT_PRIVATE_JWK}
```

The complete JWK is redacted from `toString`. The plugin supports no secret-based OAuth client
authentication. Register the corresponding public JWK and Relay scopes/claims in Mint's server-side
client registry.

## eSignet flow and claims

| Property | Default | Requirement |
|---|---:|---|
| `registry.esignet.subject-id-type` | `uin` | Internal KYC-token and PSUT subject-id type. |
| `registry.esignet.account-check-claims` | `individual_id` | Non-empty subset of `registry.relay.default-claims`. |
| `registry.esignet.claim-map.<claim>` | built-in map | eSignet claim to Relay property; `$psut` is local only. |
| `registry.esignet.auth.supported-factors` | unset | Factors exposed by the verifier. |
| `registry.esignet.auth.otp.channels` | unset | Static-demo verifier channels. |
| `registry.esignet.auth.otp.static-enabled` | `false` | Must remain false in production. |
| `registry.esignet.auth.otp.static-value` | unset | Demo-only secret. |

The default claim map includes `sub=$psut`, `individual_id`, `name`, `given_name`, `family_name`,
`birthdate`, `gender`, and `address.region`. Dotted keys can use Spring bracket binding:

```properties
registry.esignet.claim-map[address.region]=address.region
```

`doKycAuth` verifies the challenge, then calls Relay with only account-check fields. `doKycExchange`
verifies the internal token and rejects unsupported JWE before calculating the consented property
intersection. When that intersection is empty, it skips Relay entirely.

## Internal KYC token and PSUT

| Property | Default | Requirement |
|---|---:|---|
| `registry.esignet.kyc-token.hmac-secret` | required | At least 32 characters. |
| `registry.esignet.kyc-token.ttl-seconds` | `300` | Positive. |
| `registry.esignet.psut.hmac-secret` | required | At least 32 characters and different from the KYC-token key. |

## KYC/UserInfo signing

| Property | Default | Requirement |
|---|---:|---|
| `registry.esignet.kyc.response-mode` | `self-contained-jws` | Current supported production mode. |
| `registry.esignet.kyc.signing.algorithm` | `RS256` | JWS algorithm. |
| `registry.esignet.kyc.signing.keystore-type` | `PKCS12` | JDK keystore type. |
| `registry.esignet.kyc.signing.keystore-path` | required | Secret-mounted keystore. |
| `registry.esignet.kyc.signing.keystore-password` | required | Secret. |
| `registry.esignet.kyc.signing.key-alias` | required | RSA signing key alias. |
| `registry.esignet.kyc.signing.key-password` | required | Secret. |

The signing key must be RSA 2048 bits or stronger. The JWS `kid` and the certificate returned by
`getAllKycSigningCertificates` use the same RFC 7638 thumbprint-derived identifier.

Generate a deployment key with the JDK toolchain, then place it in the platform secret store:

```bash
keytool -genkeypair \
  -alias esignet-relay-kyc \
  -keyalg RSA -keysize 2048 \
  -dname "CN=esignet-relay-authenticator" \
  -validity 825 \
  -storetype PKCS12 \
  -keystore kyc-signing.p12 \
  -storepass "$REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD" \
  -keypass "$REGISTRY_ESIGNET_KYC_KEY_PASSWORD"
```

Do not build the keystore into the image or commit it.

## Environment example

```properties
registry.relay.base-url=https://relay.example.gov
registry.relay.resource=civil-person
registry.relay.lookup=by-uin
registry.relay.access-profile=esignet
registry.relay.default-claims=individual_id,name,given_name,family_name,birthdate

registry.mint.token-endpoint=https://mint.example.gov/token
registry.mint.client-id=esignet-relay-authenticator
registry.mint.private-jwk=${REGISTRY_MINT_CLIENT_PRIVATE_JWK}

registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

Never log or commit private JWKs, access tokens, assertions, selectors, OTPs, HMAC keys, KYC tokens,
PSUTs, source values, problem bodies, or keystore credentials.

## Packaging in eSignet

Place the verified JAR in the plugin directory used by `esignet-with-plugins`, provide the loader and
plugin properties through the deployment configuration source, mount the private JWK and KYC signing
secrets, and restart eSignet. The plugin JAR relies on eSignet's provided integration API, Spring, and
Jackson versions and therefore does not bundle them.
