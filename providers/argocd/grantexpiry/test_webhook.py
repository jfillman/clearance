#!/usr/bin/env python3
"""I-44: the grant-expiry webhook against a real kube-apiserver (envtest binaries: etcd + kube-apiserver, no cluster, no
network). The configuration is the chart's own render (charts/clearance-argocd-agent, grantExpiry), with its clientConfig
pointed at the webhook binary running on this machine; the binary watches the same API server.

    KUBEBUILDER_ASSETS=$(setup-envtest use 1.36.2 -p path) python3 providers/argocd/grantexpiry/test_webhook.py

Needs go, helm, kubectl and openssl. Without KUBEBUILDER_ASSETS it prints "skipped" and exits 0 (exits 1 under CI=true).
Runs twice: enforce (failurePolicy Fail) and audit (Ignore). Checks the matchConditions on the API server itself (each
exclusion, another writer, a subresource, an unprotected namespace), the clock (an expired grant still marked valid is
refused in enforce, warned and annotated in audit), what an unreachable webhook does in each mode, and that no request
met a CEL error.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "crd"))
from test_admission import Apiserver, ARGO, AGENT, OTHER, H1, H3, cm, free_port  # noqa: E402

FUTURE, PAST = "2099-01-01T00:00:00Z", "2020-01-01T00:00:00Z"


def grant(name, objects, expires=FUTURE, ns="prot"):
    return {"apiVersion": "clearance.hangar.io/v1", "kind": "ClearanceGrant",
            "metadata": {"name": name, "namespace": ns, "labels": {"clearance.hangar.io/active": "true"}},
            "spec": {"subject": {"commit": "1" * 40, "tree": "d" * 64}, "expiresAt": expires,
                     "clearance": {"id": "ch-1", "tier": 2}, "objects": {k: {"rendered": v, "changed": True} for k, v in objects.items()}}}


def certs(d):
    """A CA and a serving certificate for 127.0.0.1, as cert-manager would issue them."""
    def ossl(*a):
        subprocess.run(["openssl", *a], check=True, capture_output=True)
    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d / "ca.key", "-out", d / "ca.crt",
         "-days", "1", "-subj", "/CN=grant-expiry-test-ca")
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", d / "tls.key", "-out", d / "tls.csr",
         "-subj", "/CN=127.0.0.1")
    (d / "ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    ossl("x509", "-req", "-in", d / "tls.csr", "-CA", d / "ca.crt", "-CAkey", d / "ca.key", "-CAcreateserial", "-out", d / "tls.crt",
         "-days", "1", "-extfile", d / "ext")


def render_vwc(enforce, ca_b64, url):
    """The chart's ValidatingWebhookConfiguration, with clientConfig moved from the Service to this machine."""
    out = subprocess.run(["helm", "template", "t", str(ROOT / "charts" / "clearance-argocd-agent"), "-n", "clearance-system",
                          "--set", "cluster=test", "--set", "apiURL=https://api.example.test", "--set", "coreURL=https://core.example.test",
                          "--set", "argocd.namespace=argocd-apps", "--set", "argocd.projects={tenants}",
                          "--set", "grantExpiry.enabled=true", "--set", f"grantExpiry.enforce={'true' if enforce else 'false'}",
                          "--set", "grantExpiry.tls.certManager.enabled=false", "--set", "grantExpiry.tls.existingSecret=unused",
                          "--set", f"grantExpiry.tls.caBundle={ca_b64}", "--show-only", "templates/grant-expiry.yaml"],
                         check=True, capture_output=True, text=True).stdout
    docs = [d for d in yaml.safe_load_all(out) if d]
    [vwc] = [d for d in docs if d["kind"] == "ValidatingWebhookConfiguration"]
    hook = vwc["webhooks"][0]
    assert hook["failurePolicy"] == ("Fail" if enforce else "Ignore"), hook["failurePolicy"]
    hook["clientConfig"] = {"url": url, "caBundle": hook["clientConfig"]["caBundle"]}
    vwc["metadata"]["annotations"] = {}
    return vwc


class Webhook:
    def __init__(self, binary, mode, d, kube_url, kube_ca, token_file):
        self.port, self.probe = free_port(), free_port()
        self.log = open(d / f"webhook-{mode}.log", "w")
        self.p = subprocess.Popen([binary, f"--mode={mode}", f"--argocd-user={ARGO}", f"--listen=127.0.0.1:{self.port}",
                                   f"--probe-listen=127.0.0.1:{self.probe}", f"--tls-cert-file={d / 'tls.crt'}",
                                   f"--tls-key-file={d / 'tls.key'}", f"--kube-api={kube_url}", f"--kube-ca-file={kube_ca}",
                                   f"--kube-token-file={token_file}", "--shutdown-delay=0s"], stdout=self.log, stderr=self.log)
        self.mode = mode

    def ready(self):
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.probe}/readyz?mode={self.mode}", timeout=2) as r:
                    if r.status == 200 and f"mode={self.mode}" in r.read().decode():
                        return True
            except OSError:
                pass
            time.sleep(0.5)
        return False

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def run(binary, enforce):
    mode = "enforce" if enforce else "audit"
    results, cel_errors = [], []
    with Apiserver(os.environ["KUBEBUILDER_ASSETS"]) as k:
        d = k.dir
        certs(d)
        (d / "admin.token").write_text("admintoken")
        kc = yaml.safe_load((d / "kubeconfig").read_text())
        kube_url = kc["clusters"][0]["cluster"]["server"]
        kube_ca = d / "certs" / "apiserver.crt"

        def sh(args, doc=None, who=None):
            ok, out = k.kubectl(args, doc, who)
            low = out.lower()
            if "evaluation error" in low or "compilation failed" in low or "matchcondition" in low and "error" in low:
                cel_errors.append(out)
            return ok, out

        def check(name, want, got, text=None, warn=False):
            ok, out = got
            good = ok == want and (text is None or text in out) and (("Warning:" in out and "grant-expiry" in out) == warn)
            results.append(good)
            print(("PASS " if good else "FAIL ") + f"[{mode}] {name}" + ("" if good else f"\n     ok={ok} out={out[:500]}"))

        def need(args, doc=None, who=None):
            ok, out = sh(args, doc, who)
            if not ok:
                raise RuntimeError(f"setup failed: {args}: {out}")

        need(["apply", "-f", str(ROOT / "providers" / "argocd" / "crd" / "clearancegrant-crd.yaml")])
        need(["wait", "--for=condition=Established", "crd/clearancegrants.clearance.hangar.io", "--timeout=60s"])
        for who in (ARGO, AGENT, OTHER):
            need(["create", "clusterrolebinding", "t-" + who.split(":")[-1], "--clusterrole=cluster-admin", "--user=" + who])
        for name, labels in (("prot", {"clearance.hangar.io/protected": "true"}), ("open", {})):
            need(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}})
        need(["create", "-f", "-"], grant("g1", {"/ConfigMap/app-cm": H1, "/ConfigMap/later": H1}), AGENT)

        hook = Webhook(binary, mode, d, kube_url, kube_ca, d / "admin.token")
        try:
            if not hook.ready():
                raise RuntimeError("the webhook never became ready:\n" + (d / f"webhook-{mode}.log").read_text()[-3000:])
            ca_b64 = base64.b64encode((d / "ca.crt").read_bytes()).decode()
            need(["apply", "-f", "-"], render_vwc(enforce, ca_b64, f"https://127.0.0.1:{hook.port}/validate"))
            # The configuration takes a moment: wait until an unlisted object is refused (enforce) or warned about (audit).
            for _ in range(60):
                ok, out = k.kubectl(["create", "--dry-run=server", "-f", "-"], cm("probe", H1), ARGO)
                if "grant-expiry" in out:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("the webhook configuration never took effect: " + out)

            print(f"-- the clock ({mode})")
            check("a listed ConfigMap at its hash, grant unexpired: admitted", True, sh(["create", "-f", "-"], cm("app-cm", H1), ARGO))
            check("an object the grant does not list", not enforce, sh(["create", "-f", "-"], cm("unlisted", H1), ARGO),
                  "does not list /ConfigMap/unlisted", warn=not enforce)
            # I-44: the agent stopped; the grant is past expiresAt and still valid and active. Only the clock can see it.
            need(["patch", "clearancegrant", "g1", "-n", "prot", "--type=merge", "-p", json.dumps({"spec": {"expiresAt": PAST}})], who=AGENT)
            for _ in range(40):  # the webhook's cache follows the watch
                ok, out = k.kubectl(["patch", "configmap", "app-cm", "-n", "prot", "--dry-run=server", "--type=merge", "-p", '{"data":{"k":"w"}}'], as_user=ARGO)
                if "expired" in out:
                    break
                time.sleep(0.5)
            check("I-44: an UPDATE under an expired grant still marked valid", not enforce,
                  sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v2"}}'], who=ARGO),
                  "only in expired entries", warn=not enforce)
            check("I-44: a CREATE under it", not enforce, sh(["create", "-f", "-"], cm("later", H1), ARGO), "expired", warn=not enforce)

            print(f"-- matchConditions on the API server: not called ({mode})")
            # With the grant expired every call would be refused or warned about: a silent admit means not called.
            check("another service account", True, sh(["create", "-f", "-"], cm("by-other", H1), OTHER))
            check("an admin", True, sh(["create", "-f", "-"], cm("by-admin", H1)))
            check("an unprotected namespace (namespaceSelector)", True, sh(["create", "-f", "-"], cm("x", H1, ns="open"), ARGO))
            check("a cluster-scoped Namespace (scope: Namespaced)", True,
                  sh(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "prot2",
                     "labels": {"clearance.hangar.io/protected": "true"}}}, ARGO))
            need(["create", "-f", "-"], {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "prot"},
                                         "spec": {"replicas": 1, "selector": {"matchLabels": {"a": "b"}}, "template": {"metadata": {"labels": {"a": "b"}},
                                                  "spec": {"containers": [{"name": "c", "image": "busybox"}]}}}})
            check("a subresource (scale) as Argo", True,
                  sh(["patch", "deployment", "web", "-n", "prot", "--subresource=scale", "--type=merge", "-p", '{"spec":{"replicas":2}}'], who=ARGO))
            inactive = grant("by-argo", {})
            inactive["metadata"]["labels"] = {}  # not active: a second active grant would change what the namespace admits
            check("excluded: a ClearanceGrant as Argo", True, sh(["create", "-f", "-"], inactive, ARGO))
            check("excluded: a core Event as Argo", True, sh(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Event",
                  "metadata": {"name": "e1", "namespace": "prot"}, "involvedObject": {"kind": "ConfigMap", "name": "app-cm", "namespace": "prot"},
                  "reason": "R", "message": "m"}, ARGO))
            check("excluded: an events.k8s.io Event as Argo", True, sh(["create", "-f", "-"], {"apiVersion": "events.k8s.io/v1", "kind": "Event",
                  "metadata": {"name": "e2", "namespace": "prot"}, "eventTime": "2026-11-20T12:00:00.000000Z", "reportingController": "t/x",
                  "reportingInstance": "i", "action": "A", "reason": "R", "type": "Normal",
                  "regarding": {"kind": "ConfigMap", "name": "app-cm", "namespace": "prot"}}, ARGO))
            check("excluded: Endpoints as Argo", True, sh(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Endpoints",
                  "metadata": {"name": "ep", "namespace": "prot"}}, ARGO))
            check("excluded: an EndpointSlice as Argo", True, sh(["create", "-f", "-"], {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                  "metadata": {"name": "es", "namespace": "prot"}, "addressType": "IPv4", "endpoints": []}, ARGO))
            check("excluded: a Lease as Argo", True, sh(["create", "-f", "-"], {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                  "metadata": {"name": "l", "namespace": "prot"}, "spec": {"holderIdentity": "x"}}, ARGO))
            check("called: a ConfigMap as Argo (the same write the exclusions are compared with)", not enforce,
                  sh(["create", "-f", "-"], cm("called", H1), ARGO), "grant-expiry", warn=not enforce)

            print(f"-- the grant is live again ({mode})")
            need(["patch", "clearancegrant", "g1", "-n", "prot", "--type=merge", "-p", json.dumps({"spec": {"expiresAt": FUTURE}})], who=AGENT)
            for _ in range(40):
                ok, out = k.kubectl(["patch", "configmap", "app-cm", "-n", "prot", "--dry-run=server", "--type=merge", "-p", '{"data":{"k":"w"}}'], as_user=ARGO)
                if ok and "Warning" not in out:
                    break
                time.sleep(0.5)
            check("the same UPDATE once the agent refreshes the grant: admitted, silently", True,
                  sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v3"}}'], who=ARGO))

            print(f"-- the audit annotation ({mode})")
            time.sleep(1)
            found = False
            if k.audit.exists():
                for line in k.audit.read_text().splitlines():
                    if "clearance.hangar.io/expired-grant" in line:
                        ev = json.loads(line)
                        found = found or ev.get("annotations", {}).get("clearance.hangar.io/expired-grant", "").startswith("prot/g1: ")
            results.append(found)
            print(("PASS " if found else "FAIL ") + f"[{mode}] clearance.hangar.io/expired-grant=prot/g1: ... in the API server's audit log")
        finally:
            hook.stop()

        print(f"-- the webhook is down ({mode})")
        time.sleep(1)
        check("a listed object at its hash while no webhook answers: " + ("refused (Fail)" if enforce else "admitted (Ignore)"),
              not enforce, sh(["create", "-f", "-"], cm("down", H1), ARGO), "failed calling webhook" if enforce else None)
        check("another writer while no webhook answers: not called, admitted", True, sh(["create", "-f", "-"], cm("down-other", H1), OTHER))
    results.append(not cel_errors)
    print(("PASS " if not cel_errors else "FAIL ") + f"[{mode}] no CEL error in any response" + ("" if not cel_errors else "\n" + cel_errors[0]))
    return results


def main():
    if not os.environ.get("KUBEBUILDER_ASSETS"):
        if os.environ.get("CI") == "true":
            print("FAIL: KUBEBUILDER_ASSETS is not set under CI=true")
            return 1
        print("skipped: KUBEBUILDER_ASSETS is not set (setup-envtest use 1.36.2 -p path)")
        return 0
    out = Path(tempfile.mkdtemp(prefix="grant-expiry-bin-"))
    try:
        binary = out / "grant-expiry"
        subprocess.run(["go", "build", "-o", str(binary), "./providers/argocd/grantexpiry/cmd/grant-expiry"], cwd=ROOT, check=True)
        results = run(str(binary), enforce=True) + run(str(binary), enforce=False)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
