# Operator runbook: kube-apiserver audit flags for the collector

For the owner of a cluster that the [Kubernetes audit collector](observe-k8s.md) watches (hangar-prod; hangar-dev as the
lab). **On Hangar neither cluster has any audit flag set today.** The API server flags, the policy file and the webhook
kubeconfig are files on the control-plane node; apron renders the collector, not these. Do hangar-dev first.

Nothing here has been run against a live cluster. The kubeadm argument syntax is the v1beta4 form (Kubernetes 1.31 and
later); check your kubeadm's version.

## 0. What you need

- the collector installed and healthy-or-blind (it can be installed before the flags: it reports `blind` until the
  heartbeat comes back, which is the truth);
- a CA for the **API server's client certificate**, which is *not* the cluster's CA, and the server certificate for the
  collector. Keys stay on the machine that made them: do not commit them, paste them or put them in a values file.
- the collector Service's **ClusterIP** (pin it with `webhook.service.clusterIP`) or a NodePort.

## 1. Certificates

```sh
# a CA that only signs the API server's audit client certificate
openssl ecparam -name prime256v1 -genkey -noout -out audit-client-ca.key
openssl req -x509 -new -key audit-client-ca.key -days 825 -subj "/CN=observe-audit-client-ca" -out audit-client-ca.crt

# the API server's client certificate: the name the collector allows (--allowed-client, default kube-apiserver)
openssl ecparam -name prime256v1 -genkey -noout -out apiserver-audit-client.key
openssl req -new -key apiserver-audit-client.key -subj "/CN=kube-apiserver" -out apiserver-audit-client.csr
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in apiserver-audit-client.csr -CA audit-client-ca.crt -CAkey audit-client-ca.key -CAcreateserial \
  -days 365 -extfile client.ext -out apiserver-audit-client.crt

# the collector's server certificate, with the Service's IP as an IP SAN (and its DNS name)
openssl ecparam -name prime256v1 -genkey -noout -out collector.key
openssl req -new -key collector.key -subj "/CN=clearance-observe-k8s" -out collector.csr
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:10.96.200.50,DNS:clearance-observe-k8s.clearance-system.svc\n' > server.ext
openssl x509 -req -in collector.csr -CA audit-client-ca.crt -CAkey audit-client-ca.key -CAcreateserial \
  -days 365 -extfile server.ext -out collector.crt
```

(One CA signing both is fine for a lab; a separate server CA is better.) Create the collector's Secret yourself:

```sh
kubectl -n clearance-system create secret generic clearance-observe-k8s-tls \
  --from-file=tls.crt=collector.crt --from-file=tls.key=collector.key --from-file=ca.crt=audit-client-ca.crt
```

`ca.crt` is the CA the collector trusts for the API server's client certificate. Rotate both certificates before they
expire; the collector reads them at start (restart it after replacing the Secret).

## 2. The policy

```sh
observe-k8s policy render --namespaces app-gate-api-prod,argocd > audit-policy.yaml
observe-k8s policy check audit-policy.yaml        # must say: ok ... never records a Secret body
```

(The binary is in the image: `docker run --rm ghcr.io/jfillman/clearance-observe-k8s:vX.Y.Z policy render ...`.) Use the
same `--namespaces` as the chart's `protectedNamespaces`. **Never apply a policy `policy check` fails.**

Keep a mirror the collector can read and hold to the Secret rule (set the chart's `auditPolicyMirror` to it):

```sh
kubectl -n kube-system create configmap audit-policy --from-file=audit-policy.yaml
```

`kube-system/audit-policy` is a protected ConfigMap: **every change to it is an operation on monitoring** (tier 3, an
immediate alert, the feed goes blind until the next healthy record). That is intended; do it deliberately.

## 3. The webhook kubeconfig (`webhook.kubeconfig`)

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: observe-k8s
    cluster:
      certificate-authority: /etc/kubernetes/audit/collector-ca.crt   # the CA that signed collector.crt
      server: https://10.96.200.50:8443/audit                         # the Service's ClusterIP, port 8443, path /audit
users:
  - name: kube-apiserver
    user:
      client-certificate: /etc/kubernetes/audit/apiserver-audit-client.crt
      client-key: /etc/kubernetes/audit/apiserver-audit-client.key
contexts:
  - name: default
    context: {cluster: observe-k8s, user: kube-apiserver}
current-context: default
```

The client certificate's common name (or a DNS SAN) must be in the collector's `--allowed-client` list; anything else is
refused with 403. If the API server cannot reach the ClusterIP from the host network (no kube-proxy), use a NodePort
Service and `https://127.0.0.1:<nodePort>/audit` (the server certificate then needs `IP:127.0.0.1`).

## 4. The flags

Put `audit-policy.yaml`, `webhook.kubeconfig`, `collector-ca.crt`, `apiserver-audit-client.crt` and `.key` in
`/etc/kubernetes/audit/` on the control-plane node (mode 0600 for the key, root-owned). Then add to the `kube-apiserver`
command in `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```
--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit/webhook.kubeconfig
--audit-webhook-mode=batch
--audit-webhook-version=audit.k8s.io/v1
--audit-webhook-batch-max-wait=5s
--audit-webhook-batch-max-size=100
--audit-webhook-batch-buffer-size=50000
--audit-webhook-initial-backoff=5s
--audit-webhook-truncate-enabled=true
# optional second sink on the node, so a long collector outage can be replayed by hand:
--audit-log-path=/var/log/kubernetes/audit/audit.log
--audit-log-maxage=7
--audit-log-maxbackup=5
--audit-log-maxsize=100
```

and mount the directory (and the log directory) into the pod:

```yaml
    volumeMounts:
      - {mountPath: /etc/kubernetes/audit, name: audit, readOnly: true}
      - {mountPath: /var/log/kubernetes/audit, name: audit-log}
  volumes:
    - {name: audit, hostPath: {path: /etc/kubernetes/audit, type: DirectoryOrCreate}}
    - {name: audit-log, hostPath: {path: /var/log/kubernetes/audit, type: DirectoryOrCreate}}
```

The kubelet restarts the API server when the manifest changes; the cluster's API is unavailable for a short while.
Back up the manifest first (`cp kube-apiserver.yaml /root/kube-apiserver.yaml.pre-audit`, outside the manifests
directory). The buffer size (`--audit-webhook-batch-buffer-size`, default 10000) is the cushion for a collector that is
down: events beyond it are dropped *at the API server*, and the feed goes blind instead.

### kind clusters

For a new kind cluster, in the cluster config (the host directory `./audit` holds the files of step 4):

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - {hostPath: ./audit, containerPath: /etc/kubernetes/audit, readOnly: true}
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiVersion: kubeadm.k8s.io/v1beta4
        apiServer:
          extraArgs:
            - {name: audit-policy-file, value: /etc/kubernetes/audit/audit-policy.yaml}
            - {name: audit-webhook-config-file, value: /etc/kubernetes/audit/webhook.kubeconfig}
            - {name: audit-webhook-mode, value: batch}
            - {name: audit-webhook-version, value: audit.k8s.io/v1}
            - {name: audit-webhook-batch-max-wait, value: 5s}
            - {name: audit-webhook-batch-buffer-size, value: "50000"}
          extraVolumes:
            - {name: audit, hostPath: /etc/kubernetes/audit, mountPath: /etc/kubernetes/audit, readOnly: true, pathType: DirectoryOrCreate}
```

For an existing kind cluster (this is the case on hangar-dev and hangar-prod, which have no audit flags), do step 4 on
the node itself: copy the files into the node container (`<container cli> cp` or exec; the nodes of these clusters
run under `container`, not podman) and edit `/etc/kubernetes/manifests/kube-apiserver.yaml` there. The node's kubelet
restarts the API server. A recreated cluster loses the edit: put it in the cluster config.

## 5. Verify, in this order

1. `kubectl get --raw /readyz` is ok after the restart; `kubectl -n clearance-system logs deploy/clearance-observe-k8s`
   shows no "audit batch refused".
2. Within a minute the collector's health record is healthy: `GET /v1/coverage?scope=<cluster>` has the source
   `k8s-audit-webhook` with `now: healthy`. If it is blind, the failing check names why (`webhook-delivering`: the
   heartbeat did not come back; read the collector log for refusals: 401 no certificate, 403 wrong name).
3. A direct `kubectl -n <protected ns> annotate configmap <x> test=1` appears as an exception within a minute, with your
   actor and the diff.
4. A change to a Secret in a **scratch** namespace shows the Secret's namespace and name and **no data**: look at the
   record, and at the queue directory (`strings` over the segment files finds no value).
5. `secrets-metadata-only` and `audit-policy-live` pass in the health record.

## 6. Rolling back

Restore the manifest backup (the kubelet restarts the API server). The collector reports `blind` from the next missed
heartbeat, and the core writes an audit gap: coverage is reported as lost, not as clean. Nothing the collector already
acknowledged is lost; its queue drains.

## 7. Changing the policy later

Render, `policy check`, copy to the node, restart the API server (it reads the file at start), update the mirror
ConfigMap (an alert fires: expected), and watch the health record return to healthy. A policy that records Secrets above
Metadata is caught by the collector within a heartbeat (`secrets-metadata-only` degrades the feed; bodies are cut and
never stored), but fix it at once.
