# Messaging package for sign-in codes

A Registry Messaging package for the relay's `messaging` verifier. It holds:

- an email template and an SMS template, each taking `code` and `minutes`
- the sender profiles `otp-email` and `otp-sms`
- an access profile that lets only the client `esignet-source` send only those
  two templates through those two sender profiles, with the `messaging:send` scope

Check it offline:

```sh
messagingctl check --project examples/messaging-otp
```

The `sms-gateway` provider scripts come from the Registry Messaging starter and
suit a generic JSON gateway. Replace them with scripts for your gateway, and
change the sender addresses, the client id and the limits to match your
deployment. The operator's `runtime.yaml` still has to list the client under
`authentication.oidc.allowedClients` and name the audience that the relay's
`messaging.token_resource` obtains.

See [configuration](../../docs/esignet-configuration.md) for the relay's
`messaging` block, which names these sender profiles and templates.
