# TLS between Clearance and its callers

Callers of the core and clearance-api send a projected service-account token (audience `clearance`, one hour) as a bearer
token. Over plain http anything that can watch pod traffic can replay it for up to an hour. The core and the API can serve
https beside plain http, from cert-manager certificates, and the callers can verify them. All of it is **off by default**:
with `tls.enabled` false the chart renders exactly what it did before.

## Server side

| Setting | Environment | Meaning |
|---|---|---|
| `tls.enabled` | `CLEARANCE_TLS_LISTEN` (`:8443`), `CLEARANCE_TLS_CERT_FILE`, `CLEARANCE_TLS_KEY_FILE` | a second, https listener beside the plain one. All three or none. |
| `tls.plainHttp: false` | `CLEARANCE_LISTEN=off` | no plain listener (needs the https one). The Service and the probes use https only. |

The certificate and key are read from the files again when they change (checked at most every 10 seconds, on a handshake), so a
cert-manager renewal needs no restart. A bad or half-written pair keeps the last good certificate; an unreadable pair at start stops
the start. TLS 1.2 or later.

The chart creates the certificates (`tls.certManager.enabled`, default on when TLS is on): either its own namespaced CA (a
self-signed Issuer, a CA Certificate and a CA Issuer; the install needs nothing but cert-manager) or, with
`tls.certManager.issuerRef`, an existing Issuer or ClusterIssuer such as a shared cluster CA. No Secret is made by hand. With
`tls.certManager.enabled: false`, name your own `kubernetes.io/tls` Secrets in `tls.existingSecrets`.

## The grant-expiry webhook's certificate

The agent chart's grant-expiry webhook (`charts/clearance-argocd-agent`, `grantExpiry`; [gate.md](gate.md#the-grant-expiry-webhook-i-44-built))
is called by the API server over https and uses the same scheme: a cert-manager Certificate for its Service, signed by the chart's own
namespaced CA (a self-signed Issuer, a CA Certificate and a CA Issuer, so it needs nothing but cert-manager) or by
`grantExpiry.tls.certManager.issuerRef` (a shared cluster CA). cert-manager's CA injector writes the ValidatingWebhookConfiguration's
`caBundle`; no trust-manager Bundle is involved, since the API server is the only client. Without cert-manager, name a `kubernetes.io/tls`
Secret (`grantExpiry.tls.existingSecret`) and its CA (`grantExpiry.tls.caBundle`). The certificate is re-read when it changes.

## Client side

Every client takes an optional CA file (`CLEARANCE_CA_FILE`, or `--ca-file`): extra roots trusted **besides** the system roots,
for a private CA. The server is always verified; there is no skip setting. A missing or empty CA file stops the client at start.

| Client | Setting |
|---|---|
| Argo CD plugin (CMP) sidecar | `CLEARANCE_URL=https://...`, `CLEARANCE_CA_FILE` |
| wait Job (PreSync) | the plugin injects it; `CLEARANCE_WAIT_CA_CONFIGMAP` on the plugin names the ConfigMap it mounts at `/etc/clearance-ca/ca.crt` |
| agent (`charts/clearance-argocd-agent`) | `apiURL`, `coreURL` as https, `tls.caConfigMap`, `waitJob.caConfigMap` |
| observe-aws, Go `client` package | `CLEARANCE_CA_FILE`, `client.Options.CAFile` |

The CA must reach each client's namespace as a ConfigMap (a public certificate, never the key). With the chart's own CA that is the
`ca.crt` key of the `<release>-<core|api>-tls` Secret in the release namespace: copy the certificate (not the key) to a ConfigMap,
or let trust-manager publish it. With a shared cluster CA, trust-manager's `Bundle` is the cleaner way (one source, a ConfigMap in
every namespace that asks for it); a Bundle can read its source only from the trust namespace.

## Rollout order (no gate is interrupted)

1. Turn TLS on beside plain http (`tls.enabled: true`). The core restarts once (Recreate). Plain callers are untouched.
2. Distribute the CA ConfigMap to the clients' namespaces.
3. Move clients one at a time: the agent, the plugin sidecar, then the wait Job's pin and the admission policy's matching optional
   volume. Each moves its URL to `https://...:8443` and gains its CA.
4. When no client is on plain http, set `tls.plainHttp: false`. Not supported yet while the web UI, clearance-slack, clearance-grc or
   an HTTPRoute is enabled (they call over plain http and have no CA setting): the chart refuses it.

Rollback: set `tls.plainHttp: true` (and the clients' URLs back to http); then `tls.enabled: false`.

## Known limits

- The admission policy's wait-Job exemption (`providers/argocd/crd/admission.yaml`) admits the optional CA volume and mount
  exactly as the plugin builds it: a second volume `clearance-ca`, a ConfigMap volume of the pinned ConfigMap with the one item
  `ca.crt`, mounted read-only at `/etc/clearance-ca`, after the token's. The installer renders the pinned name
  (`ca-bundle.invalid` in the file) from the same value it gives the plugin's `CLEARANCE_WAIT_CA_CONFIGMAP`, and renders the policy
  first: a Job with the CA volume is refused by a policy without it. The agent's validator knows the same shape (`WaitPin.CAConfigMap`).
- Moving the wait Job's URL (`http://...:8080` to `https://...:8443`) changes the URL the policy pins. For one release the policy may
  also admit the previous URL (`clearance-core-previous.invalid` in the file; Apron's `clearance.gate.previousURL`), so a wait Job or
  cached manifest made before the change is not refused where the binding denies. The agent's exception scan pins one URL only.
- The web UI, clearance-slack and clearance-grc still call the core and the API over plain http.
