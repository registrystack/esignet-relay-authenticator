# Provider configuration

Select `MOSIP_ESIGNET_AUTHN_PROVIDER=breg` and mount the file named by
`REGISTRY_ESIGNET_CONFIG_FILE`. Only one YAML document is accepted. Configuration
and secret files are read during provider construction; restart after rotation.
There are no Spring or legacy Java property aliases.

Set `MOSIP_ESIGNET_HOST` to the externally visible eSignet URL, for example
`https://esignet.example.org`. GA uses it to expand resource-server identifiers
in the bundled `deployment.yaml`; an unset host makes those identifiers relative
and startup rejects them.

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

A deployment chooses one of three ways to verify a challenge:

1. Registry Messaging, configured by the `messaging` block. This is the
   production path.
2. A verifier of your own, supplied through
   `provider.New(cfg, provider.WithChallengeVerifier(verifier))`.
3. A synthetic demo verifier (static code or Mailpit), for local flows only.

They are mutually exclusive. The provider refuses to start when `messaging` is
combined with a `demo` verifier or with an injected verifier, and when the
`messaging` block is incomplete.

### Registry Messaging (production)

The provider asks [Registry Messaging](https://registrystack.org) to send the
code. Messaging renders one reviewed template and sends it through the email or
SMS provider the operator configured. A request for a code works like this:

1. The provider reserves room for one pending code, then looks the person up in
   BREG through the configured access profile. One lookup reads the account-check
   fields and the contact field of every channel that is both requested and
   configured. eSignet requests every channel the provider advertises.
2. If the person is unknown or ineligible, or has no valid contact for any of
   those channels, it sends nothing and returns the same result as a successful
   send. Otherwise it uses the first channel with a valid contact, in the fixed
   order email, then phone.
3. It generates a six-digit code, keeps a salted digest, starts the Messaging
   call in the background and returns. The message carries an `expiresAt` equal to
   the code's expiry, so Messaging does not start a delivery after the code has
   expired. It cannot stop a delivery that is already under way and delayed.

A contact is valid when Registry Messaging would accept it as a recipient. An
email address is one `local@domain` of visible ASCII, with a dotted domain that
neither starts nor ends with a dot, and none of `< > , ;`. A phone number is E.164.

```yaml
breg:
  # ... as above, plus the contact fields the register exposes
  provisioned_fields: [uin, status, givenName, familyName, email-address, phone-number]
messaging:
  base_url: https://messaging.example.org
  token_resource: urn:messaging:production
  token_scopes: [messaging:send]
  code_ttl_seconds: 300
  resend_cooldown_seconds: 60
  max_sends_per_hour: 5
  max_tracked_people: 100000
  max_pending_codes: 100000
  contact_fields:
    email: email-address
    phone: phone-number
  channels:
    email:
      sender_profile: otp-email
      template_id: sign-in-code-email
      template_version: "1"
      locale: en
    phone:
      sender_profile: otp-sms
      template_id: sign-in-code-sms
      template_version: "1"
      locale: en
```

| Key | Meaning |
| --- | --- |
| `base_url` | Messaging's URL. HTTPS unless `http.allow_insecure_http` is set. |
| `token_resource`, `token_scopes` | The resource and scopes requested for the Messaging access token. The issuer must set Messaging's audience for them. |
| `code_ttl_seconds` | Code lifetime. Default 300, from 60 to 900. |
| `resend_cooldown_seconds` | Minimum gap between sends to one person on one transaction. Default 60, up to 3600, and at least twice `http.timeout_seconds` (20 with the default timeout), so two sends for one person never overlap. A smaller value is refused at startup. |
| `max_sends_per_hour` | Sends to one person in any hour, across transactions. Default 5, from 1 to 60. |
| `max_tracked_people` | People the limiter tracks at once. Default 100000, from 1 to 10000000. |
| `max_pending_codes` | Pending entries at once, one per admitted request. Default 100000, from 1 to 1000000. |
| `contact_fields` | The BREG field holding the contact for each channel. Each must appear in `breg.provisioned_fields`. |
| `channels` | One entry per offered channel, `email` or `phone`. Only configured channels are advertised to eSignet. |

Each channel names the Messaging sender profile, the template id and version,
and one locale. The template receives two values, `code` (a string of six digits)
and `minutes` (the whole minutes until expiry). A phone number must be in E.164
form. [examples/messaging-otp](../examples/messaging-otp) holds an email
template, an SMS template, their sender profiles and an access profile that lets
only this client send only those templates. Check it with `messagingctl check`.

The token request reuses `token_client`: the same client identity, the same
private key file and the same issuer endpoint, with Messaging's own resource and
scopes. Messaging must list the client in its `allowedClients`, and its access
profile must list the client, the scopes, the sender profiles and the templates.
The `http` settings (timeout, CA file, response limit and the insecure HTTP
rule) apply to Messaging calls too.

Each send carries a random `Idempotency-Key`. The provider does not retry it,
but Go's HTTP transport may replay it once on a stale keep-alive connection.
That is harmless, because Messaging answers a repeated key and body with the
stored receipt.

The call runs on its own context with a timeout of twice `http.timeout_seconds`,
and at most 64 calls run at once. The 64 is fixed, not configurable, and a call
past that limit is dropped and reported as `send-dropped`. The caller sees a
successful send in every case, so the operator needs a signal.

The shipped image logs one warning line per event through the host logger, with
the event kind in an `event` field and fixed text otherwise. Library users pass
`provider.WithOperatorSignal(func(provider.OperatorEvent) {})` to `provider.New`.
It must be safe for concurrent use and must not block, and the provider contains
a panic in it. Both receive one of these fixed kinds and never a code, contact,
identifier or Messaging response:

| Event | Meaning | What happened to the code |
| --- | --- | --- |
| `send-refused` | Messaging answered with a 4xx, for example a rate limit or an unknown template. | The earlier code, if any, is restored. The cooldown and budget stay spent. |
| `send-failed` | The call could not be made or its outcome is unknown, for example a timeout. | Kept, in case the message arrives. The cooldown and budget stay spent. |
| `send-dropped` | 64 calls were already running. | Not sent. The cooldown and budget stay spent. |
| `limiter-full` | The limiter is at `max_tracked_people`. The request was refused. | None issued. |
| `store-full` | The pending store is at `max_pending_codes`. The request was refused. | None issued. |

Every sign-in code shares Messaging's access profile limits, so a rate limit
there refuses sends for everyone until it passes. Watch `send-refused`.

### Limits and bounds

All limits are held in process memory, keyed per person by an HMAC of the
identifier type and identifier under a random key that lives as long as the
process. A restart clears them.

| Limit | Default | At the limit |
| --- | --- | --- |
| Resend cooldown, per person and transaction | 60 s | The request returns as for a successful send and nothing is sent. The earlier code stays valid until it expires. |
| Sends per person per hour | 5 | The same silent result until the hour passes. |
| Failed verifications per person | 10 per hour | Counted only for a code that was requested. Codes stop being issued and accepted for that person until the hour ends. A send is silent and a verification answers as for a wrong code. A success resets the count. |
| Attempts per code | 5 | The code is consumed. |
| People tracked (`max_tracked_people`) | 100000 | Every request fails as unavailable and raises `limiter-full`, including one from a person already tracked. Entries with nothing live are dropped first. |
| Pending entries (`max_pending_codes`) | 100000 | Every request fails as unavailable and raises `store-full`, whoever it names. Expired entries are dropped first. |

Every admitted request stores one pending entry and counts against its person,
whether or not a message is sent, so neither bound reveals who exists. The
limiter and the store are pruned at most once a second, not on every request.

Practical ceilings. At the default of 100000 people, a deployment signs in about
28 distinct people a second sustained over an hour (100000 divided by 3600). A
pending entry lives five minutes by default, so the store allows about 333
requests a second, and the limiter is the tighter bound. Measured on a
development machine, a limiter entry takes about 840 bytes and a pending entry
about 240 bytes (more for long identifiers), so the defaults hold roughly 84 MB
and 24 MB, and one once-a-second prune of 100000 entries takes about 20 ms. Past
a bound, new requests are refused as unavailable until entries expire. Raise the
bound for a larger deployment and budget memory from these figures.

Because every request names a person, each bound can be used up by guessing
identifiers. Run a per-client rate limit in front of eSignet. The provider does
not rate limit by caller.

The per-person limits can be used against a named person. Anyone who knows an
identifier can use up its hourly budget with a few requests, so that person is
told a code was sent while nothing arrives, for up to an hour. Nothing is
refunded, so a person who retries during a Messaging outage can use up their own
hourly budget and be held silently after the outage ends. A wrong code locks a
person only after they requested a code, and ten failures an hour is the
ceiling, so sustained, loud guessing against one person reaches about 240 guesses
a day. Any per-person limit has this weakness. Edge rate limiting is the
mitigation.

What this does not hide:

- Messaging's API never returns the recipient, the rendered message or the
  template data. It keeps them for its payload retention period (1 to 30 days,
  default 7). The exposure is a live code during its validity for whoever can
  read Messaging's database or backups, and for the email or SMS provider.
- Pending codes and limits live in one process. Run one replica or route each
  eSignet session to the same replica. Per-person limits multiply by the number
  of replicas. A restart drops pending codes.

### Bring your own verifier

A production adapter supplies the Go interface through
`provider.New(cfg, provider.WithChallengeVerifier(verifier))`. Its `Verify`
method must authenticate the exact identifier and binding in the request.
`SendOTP` initiates that same challenge through the institution's delivery
system. Implementations must honor context cancellation and never log challenge
or subject values. Verification failure stops before token acquisition and BREG.

### Synthetic demo verifiers

The shipped factory has no implicit verifier. It fails startup unless Messaging is
configured, a real verifier is injected or synthetic mode is explicitly enabled:

```yaml
demo:
  static_otp_enabled: true
  static_otp_file: /run/secrets/demo-otp
```

Synthetic mode accepts that one configured value and sends no email or SMS.
It proves flow composition only, not the identity of a person. Solmara's
fictional fixtures use this mode explicitly. Enrollment, signup, password,
biometrics and wallet authentication are not exposed by this integration.

For a local Mailpit flow, replace the static mode with:

```yaml
demo:
  mailpit:
    enabled: true
    smtp_address: mailpit:1025
    sender: esignet-demo@example.test
    recipient: synthetic-inbox@example.test
```

Start Mailpit on the same local compose network and open its inbox UI to read
the delivered six-digit code. The SMTP address accepts only `mailpit`,
`localhost`, or an IP loopback address with an explicit port. The recipient is
one fixed synthetic inbox, never derived from the person's identifier or BREG
attributes. Only email is advertised. Codes expire in five minutes, allow at
most five wrong attempts, and are consumed on success. They bind the exact
identifier/type, relying party, client and transaction. The process retains at
most 100000 pending challenges and loses them on restart. SMTP delivery
failure creates no new challenge. This mode uses unencrypted local SMTP and cannot
establish ownership of a real email address or a person's identity. Keep it
restricted to synthetic local demonstrations. A production integration uses
Registry Messaging or supplies its own `ChallengeVerifier`.

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
