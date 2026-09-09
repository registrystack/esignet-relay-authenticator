# Solmara BREG identity integration

The companion Solmara Lab contains a synthetic population registry authored for
BREG and an isolated native eSignet fixture. This provider uses BREG directly;
other lab Relay services are independent and are not used by this login flow.

## Components

- Native BREG and PostgreSQL hold synthetic population records.
- Native Registry Mint issues short-lived credentials to the lookup-only client.
- The candidate eSignet image embeds this provider and the OTP/consent flow.
- Separate eSignet PostgreSQL, Redis and host key volumes hold its runtime state.
- The matching eSignet UI and Solmara Portal complete a verified OIDC login.

Build the candidate using this repository's `integration/build.sh`. Follow the
lab's `docs/esignet.md` for exact fixture startup and credential export commands.
Use the same source pins and candidate image in local validation and any later
hosted rollout. Hosted overlays prepare configuration only; they do not imply a
published or deployed release.

## Verification

The local journey must verify challenge rejection before BREG/Mint, minimal
account projection, explicit consent, optional refusal on repeated logins,
required-claim refusal, signed UserInfo verification and subject correlation.
An independent encrypted-UserInfo client exercises the host encryption path.
The BREG source client must fail list and write attempts and must not retrieve
inactive or ungranted identities or fields.

Use separate candidate volumes and never reuse or remove an existing Java
installation's database, Redis or keys during this exercise. Existing release
artifacts remain unchanged. Candidate publication and hosted cutover are
separate operator actions after validation.
