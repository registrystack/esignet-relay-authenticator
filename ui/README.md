# eSignet companion UI

This image serves the UI from the exact eSignet commit in
`integration/upstream.env`. The build checks that archive's SHA256, applies the
reviewed English-default and dependency patches, verifies the patched npm
lockfile SHA256, and runs `npm ci`. The runtime contains static files and nginx,
without Node, test tools, or the upstream plugin download/startup script.

For an isolated local candidate on the Docker daemon's architecture:

```sh
CANDIDATE_IMAGE=esignet-oidc-ui:local-candidate ./integration/build.sh --ui --load
ui/smoke.sh esignet-oidc-ui:local-candidate
```

The release build uses `./integration/build.sh --ui` to export the multi-platform
OCI candidate with source labels, SBOM, and provenance. A local candidate tag is
not a publication pin. `ui/smoke.sh` also accepts an image imported from that
archive and checks static serving, public proxy, private-route refusal, and
access-log privacy in an isolated Docker network.

Run the UI on the same private container network as the provider, where the
provider is reachable as `esignet:8080`. Expose the UI's port 3000 through a
deployment-owned outer proxy. The UI and public OIDC routes share one origin;
only the reviewed OIDC, flow, CSRF, design, and i18n paths proxy to the
provider. Client management and administration remain private. The nginx
configuration limits access logs to method, path, and status, omitting query
strings and credentials. A real OIDC browser journey is still required before
cut-over.
