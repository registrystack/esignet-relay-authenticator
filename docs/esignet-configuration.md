# Provider configuration

Select `MOSIP_ESIGNET_AUTHN_PROVIDER=breg` and mount the file named by
`REGISTRY_ESIGNET_CONFIG_FILE`. Only one YAML document is accepted. Configuration
and secret files are read during provider construction; restart after rotation.
There are no Spring or legacy Java property aliases.

```yaml
subject_id_type: uin
psut_secret_file: /run/secrets/registry-psut
breg:
  base_url: https://population.example.org
  route: population
  selector: by-uin
  selector_field: uin
  access_profile: esignet-source
  provisioned_fields: [uin, status, givenName, familyName, birthdate, gender]
  account_check_fields: [uin, status]
token_client:
  token_endpoint: https://issuer.example.org/oauth2/token
  assertion_audience: https://issuer.example.org/oauth2/token
  client_id: esignet-source
  private_key_file: /run/secrets/registry-client.jwk
  key_id: esignet-source-2026-09
  resource: urn:breg:population
  scopes: [registry.read, records.lookup]
claim_map:
  sub: $psut
  given_name: givenName
  family_name: familyName
  birthdate: birthdate
  gender: gender
http:
  timeout_seconds: 10
  max_response_bytes: 1048576
demo:
  static_otp_enabled: false
```

The BREG package must grant the configured selector and fields to this workload.
Its row authorization determines which identities are eligible. Use a separate
client for seeding or administering records; the identity provider needs neither
list nor write access. The configured account-check set must be a nonempty
subset of the provisioned inventory.

Only explicitly consented and mapped claims are requested. `$psut` is a local
source token, never a BREG property. Protocol claims cannot be replaced with
registry fields. Registry Record metadata is never mapped into UserInfo.

## Secrets and transport

The PSUT file must contain at least 32 bytes of independent random secret
material. It is not the token client key, an OTP, or an eSignet signing key.
Persisting this key preserves subjects across restarts; replacing it changes
subjects.

The token client key file accepts an ES256 P-256 or RS256 RSA private JWK. RSA
keys must be at least 2048 bits. A PEM PKCS8/PKCS1 key is also accepted with
explicit `token_client.key_id`. The configured key ID is required and must match
a JWK's `kid`. Store private keys as operator-owned secrets outside the container
image.

`token_client.token_endpoint`, `assertion_audience`, `client_id`,
`private_key_file`, `key_id`, `resource`, and `scopes` are all explicit. This
keeps the provider independent of issuer discovery and prevents request-time
callers from changing the token's intended service or authority. The resource
must be one absolute URI without a fragment or userinfo, and scopes must be a
nonempty list of OAuth scope tokens. The client sends that exact resource and
the scopes joined by one space on every `client_credentials` request. Assertions
default to 120 seconds and token caching to at most 300 seconds, further
shortened by the issuer's returned lifetime. `client_secret` is not accepted.
The retired top-level `mint` key is rejected with a migration diagnostic and has
no alias.

HTTPS is required by default. `http.ca_file` adds a PEM CA bundle to system
trust. `http.allow_insecure_http: true` is an explicit local-fixture setting;
use authenticated TLS for operated services. Redirects are not followed.

## Challenge verification

A production adapter supplies the Go interface through
`provider.New(cfg, provider.WithChallengeVerifier(verifier))`. Its `Verify`
method must authenticate the exact identifier and binding in the request.
`SendOTP` initiates that same challenge through the institution's delivery
system. Implementations must honor context cancellation and never log challenge
or subject values. Verification failure stops before token acquisition and BREG.

The shipped factory has no implicit production verifier. It fails startup
unless a real verifier is injected or synthetic mode is explicitly enabled:

```yaml
demo:
  static_otp_enabled: true
  static_otp_file: /run/secrets/demo-otp
```

Synthetic mode accepts that one configured value and sends no email or SMS.
It proves flow composition only, not the identity of a person. Solmara's
fictional fixtures use this mode explicitly. Enrollment, signup, password,
biometrics and wallet authentication are not exposed by this integration.

## eSignet configuration

Use the supplied `flow-breg-otp` flow. It includes OTP initiation/verification,
authorization, fresh consent and assertion. The consent wrapper forces a new
prompt for each flow, including repeated logins with an unchanged claim set.

The engine's prerequisite call uses nil requested attributes before consent;
the adapter rejects that call without consuming its attribute context. An
approved empty set succeeds without consulting BREG. This distinction is part
of the supported integration contract.

Configure PostgreSQL, Redis, keymanager, public issuer and UI through the pinned
eSignet runtime settings. The provider does not own those systems. The
synthetic fixture explicitly enables upstream's software PKCS12 keystore;
production key custody remains a deployment concern. Final signed or encrypted
UserInfo is generated by eSignet according to its client registration.
