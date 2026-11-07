#!/usr/bin/env python3
"""G-ARGO-2: the ClearanceGrant CRD and the two admission policies, proven against a real kube-apiserver (envtest
binaries: etcd + kube-apiserver, no cluster, no network). No keys, no tokens: users are impersonated.

    KUBEBUILDER_ASSETS=$(setup-envtest use 1.36.2 -p path) python3 providers/argocd/crd/test_admission.py

Without KUBEBUILDER_ASSETS it prints "skipped" and exits 0 (exits 1 under CI=true). Runs the whole matrix twice: Deny (both fields flipped)
and Warn (the shipped mode: every refusal becomes a warning, nothing is refused, no active grant is allowed).
It also fails on any CEL evaluation error and checks the grant name reaches the API server's audit log.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ARGO = "system:serviceaccount:argocd-apps:argocd-application-controller"
AGENT = "system:serviceaccount:clearance-system:clearance-argocd-agent"
OTHER = "system:serviceaccount:default:somebody-else"
H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Apiserver:
    def __init__(self, assets):
        self.assets = Path(assets)
        self.dir = Path(tempfile.mkdtemp(prefix="clearance-vap-"))
        self.procs = []
        self.audit = self.dir / "audit.log"

    def __enter__(self):
        d = self.dir
        subprocess.run(["openssl", "genrsa", "-out", d / "sa.key", "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", d / "sa.key", "-pubout", "-out", d / "sa.pub"], check=True, capture_output=True)
        (d / "tokens.csv").write_text("admintoken,admin,admin,system:masters\n")
        (d / "audit-policy.yaml").write_text(
            "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n  resources: [{group: '', resources: [configmaps]}]\n")
        ec, ep, ap = free_port(), free_port(), free_port()
        log = open(d / "etcd.log", "w")
        self.procs.append(subprocess.Popen([self.assets / "etcd", "--data-dir", d / "etcd",
                                            "--listen-client-urls", f"http://127.0.0.1:{ec}",
                                            "--advertise-client-urls", f"http://127.0.0.1:{ec}",
                                            "--listen-peer-urls", f"http://127.0.0.1:{ep}"], stdout=log, stderr=log))
        log = open(d / "apiserver.log", "w")
        self.procs.append(subprocess.Popen([self.assets / "kube-apiserver", "--etcd-servers", f"http://127.0.0.1:{ec}",
                                            "--cert-dir", d / "certs", "--secure-port", str(ap), "--bind-address", "127.0.0.1",
                                            "--service-account-issuer", "https://clearance-vap.test",
                                            "--service-account-key-file", d / "sa.pub",
                                            "--service-account-signing-key-file", d / "sa.key",
                                            "--token-auth-file", d / "tokens.csv", "--authorization-mode", "RBAC",
                                            "--allow-privileged=true", "--audit-policy-file", d / "audit-policy.yaml", "--audit-log-path", self.audit,
                                            "--service-cluster-ip-range", "10.0.0.0/24"], stdout=log, stderr=log))
        (d / "kubeconfig").write_text(yaml.safe_dump({
            "apiVersion": "v1", "kind": "Config", "current-context": "t",
            "clusters": [{"name": "t", "cluster": {"server": f"https://127.0.0.1:{ap}", "insecure-skip-tls-verify": True}}],
            "users": [{"name": "admin", "user": {"token": "admintoken"}}],
            "contexts": [{"name": "t", "context": {"cluster": "t", "user": "admin"}}]}))
        self.kubeconfig = str(d / "kubeconfig")
        for _ in range(90):
            if self.kubectl(["get", "--raw", "/readyz"])[0]:
                return self
            time.sleep(1)
        raise RuntimeError(f"kube-apiserver did not become ready; see {d}/apiserver.log")

    def __exit__(self, *exc):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)

    def kubectl(self, args, doc=None, as_user=None):
        cmd = [shutil.which("kubectl") or "kubectl", "--kubeconfig", self.kubeconfig]
        if as_user:
            cmd += ["--as", as_user, "--as-group", "system:serviceaccounts", "--as-group", "system:authenticated"]
        r = subprocess.run(cmd + args, input=json.dumps(doc) if doc is not None else None, capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()


def cm(name, rendered=None, ns="prot", **extra):
    md = {"name": name, "namespace": ns}
    md.update(extra)
    if rendered:
        md["annotations"] = {"clearance.hangar.io/rendered": rendered}
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": md, "data": {"k": "v"}}


def deploy(name, rendered, ns="prot"):
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": ns, "annotations": {"clearance.hangar.io/rendered": rendered}},
            "spec": {"selector": {"matchLabels": {"a": "b"}},
                     "template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": [{"name": "c", "image": "busybox"}]}}}}


WAIT_IMAGE = "registry.invalid/clearance-wait@sha256:" + "0" * 64
CORE_URL = "http://clearance-core.invalid:8080"


def wait_job(name, image=WAIT_IMAGE, label="wait", hook="PreSync", ns="prot", extra_volume=False, token="clearance",
             host=None, privileged=False, command=None, args=None, env=None, env_from=False, aliases=False, init=False,
             pod=None, ctr=None, job=None, automount=False):
    ctr_extra = ctr
    """The Job exactly as providers/argocd/cmp/job.go builds it, with one deviation per call."""
    md = {"name": name, "namespace": ns, "annotations": {"argocd.argoproj.io/hook": hook}}
    if label:
        md["labels"] = {"clearance.hangar.io/injected": label}
    ctr = {"name": "wait", "image": image,
           "args": args if args is not None else ["--change", "ch-1", "--timeout", "1h0m0s"],
           "env": env if env is not None else [{"name": "CLEARANCE_URL", "value": CORE_URL},
                                               {"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"}],
           "volumeMounts": [{"name": "clearance-token", "mountPath": "/var/run/secrets/tokens", "readOnly": True}]}
    if privileged:
        ctr["securityContext"] = {"privileged": True}
    if command:
        ctr["command"] = command
    if env_from:
        ctr["envFrom"] = [{"secretRef": {"name": "anything"}}]
    ctr.update({"imagePullPolicy": "IfNotPresent", "terminationMessagePolicy": "FallbackToLogsOnError",
                "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}}})
    ctr.setdefault("securityContext", {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                       "capabilities": {"drop": ["ALL"]}})
    ctr.update(ctr_extra or {})
    spec = {"restartPolicy": "Never", "containers": [ctr],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "clearance-token", "projected": {"sources": [
                {"serviceAccountToken": {"audience": token, "expirationSeconds": 3600, "path": "clearance"}}]}}]}
    if extra_volume:
        spec["volumes"].append({"name": "v", "emptyDir": {}})
    if host:
        spec[host] = True
    if aliases:
        spec["hostAliases"] = [{"ip": "10.9.9.9", "hostnames": ["clearance-core.invalid"]}]
    if init:
        spec["initContainers"] = [{"name": "i", "image": image}]
    if automount is not None:
        spec["automountServiceAccountToken"] = automount
    spec.update(pod or {})
    jspec = {"backoffLimit": 0, "activeDeadlineSeconds": 3900, "template": {"metadata": {"labels": md.get("labels", {})}, "spec": spec}}
    jspec.update(job or {})
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": md, "spec": jspec}


def grant(name, objects, active=True, ns="prot"):
    return {"apiVersion": "clearance.hangar.io/v1", "kind": "ClearanceGrant",
            "metadata": {"name": name, "namespace": ns, "labels": {"clearance.hangar.io/active": "true"} if active else {}},
            "spec": {"subject": {"commit": "1" * 40, "tree": "d" * 64}, "expiresAt": "2099-01-01T00:00:00Z",
                     "clearance": {"id": "ch-1", "tier": 2, "policy": {"name": "deploy", "version": "1"}},
                     "signature": "dGVzdA==",
                     "objects": {k: {"rendered": v, "changed": True} for k, v in objects.items()}}}


def load_policies(deny):
    docs = list(yaml.safe_load_all((HERE / "admission.yaml").read_text()))
    for d in docs:
        if d["kind"] == "ValidatingAdmissionPolicyBinding":
            d["spec"]["validationActions"] = ["Deny", "Audit"] if deny else ["Warn", "Audit"]
            if "paramRef" in d["spec"]:
                d["spec"]["paramRef"]["parameterNotFoundAction"] = "Deny" if deny else "Allow"
    return docs


def run(deny):
    mode = "Deny" if deny else "Warn"
    results = []
    cel_errors = []

    with Apiserver(os.environ["KUBEBUILDER_ASSETS"]) as k:
        def sh(args, doc=None, who=None):
            ok, out = k.kubectl(args, doc, who)
            low = out.lower()
            if "evaluation error" in low or "compilation failed" in low or "cel" in low and "error" in low:
                cel_errors.append(out)
            return ok, out

        def check(name, want, got, expect_text=None, warn=None):
            """want: True = admitted, False = refused. In Warn mode a refusal is an admit that carries a warning."""
            ok, out = got
            if not deny and want is False:
                want = True
                warn = True if warn is None else warn
            if warn is None:
                warn = False
            warned = "Warning: Validation failed" in out
            good = ok == want and (not expect_text or expect_text in out) and (warned == warn if want else True)
            results.append(good)
            print(("PASS " if good else "FAIL ") + f"[{mode}] {name}" + ("" if good else f"\n     ok={ok} warned={warned} out={out[:400]}"))

        def need(args, doc=None, who=None):
            ok, out = sh(args, doc, who)
            if not ok:
                raise RuntimeError(f"setup failed: {args}: {out}")

        need(["apply", "-f", str(HERE / "clearancegrant-crd.yaml")])
        need(["wait", "--for=condition=Established", "crd/clearancegrants.clearance.hangar.io", "--timeout=60s"])
        for who in (ARGO, AGENT, OTHER):  # RBAC allows all three everything; the policies are what is under test
            need(["create", "clusterrolebinding", "t-" + who.split(":")[-1], "--clusterrole=cluster-admin", "--user=" + who])
        for name, labels in (("prot", {"clearance.hangar.io/protected": "true"}), ("open", {})):
            need(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}})
        need(["apply", "-f", "-"], {"apiVersion": "v1", "kind": "List", "items": load_policies(deny)})

        def settle():
            # The policy controller needs a moment: wait until the grant-writer policy refuses (Deny) or warns (Warn).
            for _ in range(60):
                ok, out = k.kubectl(["create", "-f", "-"], grant("probe", {}), OTHER)
                if (not ok and "only the Clearance grant-sync agent" in out) or (ok and "Warning:" in out):
                    k.kubectl(["delete", "clearancegrant", "probe", "-n", "prot"])
                    return
                if ok:
                    k.kubectl(["delete", "clearancegrant", "probe", "-n", "prot"])
                time.sleep(1)
            raise RuntimeError("policies never took effect: " + out)
        settle()
        time.sleep(2)

        print(f"-- ClearanceGrant: who writes it ({mode})")
        g = grant("g1", {"/ConfigMap/app-cm": H1, "apps/Deployment/web": H2, "/ConfigMap/later": H1})
        check("another user cannot create a grant", False, sh(["create", "-f", "-"], g, OTHER), "only the Clearance grant-sync agent")
        sh(["delete", "clearancegrant", "g1", "-n", "prot", "--ignore-not-found"])
        check("an admin cannot create a grant either", False, sh(["create", "-f", "-"], g), "only the Clearance grant-sync agent")
        sh(["delete", "clearancegrant", "g1", "-n", "prot", "--ignore-not-found"])
        check("the agent creates the grant", True, sh(["create", "-f", "-"], g, AGENT))
        check("the agent writes status.valid", True, sh(["patch", "clearancegrant", "g1", "-n", "prot", "--subresource=status",
              "--type=merge", "-p", '{"status":{"valid":true,"reason":"verified"}}'], who=AGENT))
        check("another user cannot write status.valid", False, sh(["patch", "clearancegrant", "g1", "-n", "prot",
              "--subresource=status", "--type=merge", "-p", '{"status":{"valid":true}}'], who=OTHER), "only the Clearance grant-sync agent")
        if deny:
            check("the CRD refuses a grant whose objects entry has no hash", False,
                  sh(["create", "-f", "-"], dict(grant("bad", {}), spec={"subject": {"tree": "d" * 64}, "expiresAt": "2099-01-01T00:00:00Z",
                     "objects": {"/ConfigMap/x": {"changed": True}}}), AGENT), "rendered")
            check("the namespace controller's kind of write (DELETE) is not refused", True,
                  sh(["delete", "clearancegrant", "g1", "-n", "prot", "--dry-run=server"], who=OTHER))

        print(f"-- protected writes: Argo's application-controller ({mode})")
        check("admit: a listed ConfigMap at its hash", True, sh(["create", "-f", "-"], cm("app-cm", H1), ARGO))
        check("admit: a listed Deployment (apps group) at its hash", True, sh(["create", "-f", "-"], deploy("web", H2), ARGO))
        check("admit: an update of a listed object", True,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v2"}}'], who=ARGO))
        check("refuse: an object the grant does not list", False, sh(["create", "-f", "-"], cm("unlisted", H1), ARGO),
              "does not list /ConfigMap/unlisted")
        check("refuse: a listed name, not created yet, at another hash (create)", False,
              sh(["create", "-f", "-"], cm("later", H3), ARGO), "does not list /ConfigMap/later at " + H3)
        check("refuse: a listed name with the wrong hash (update)", False,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p",
                  '{"metadata":{"annotations":{"clearance.hangar.io/rendered":"' + H3 + '"}}}'], who=ARGO), "at " + H3)
        sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p",  # Warn lets the refused write land: undo it
           '{"metadata":{"annotations":{"clearance.hangar.io/rendered":"' + H1 + '"}}}'])
        check("refuse: no rendered annotation (has() guard on annotations)", False, sh(["create", "-f", "-"], cm("bare"), ARGO),
              "no clearance.hangar.io/rendered annotation")
        check("refuse: generateName, no name (has() guard on name)", False,
              sh(["create", "-f", "-"], {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"generateName": "gen-", "namespace": "prot", "annotations": {"clearance.hangar.io/rendered": H1}}}, ARGO),
              "does not list /ConfigMap/")
        check("not matched: a protected namespace, another writer (admin)", True, sh(["create", "-f", "-"], cm("by-admin"), None))
        check("not matched: a protected namespace, another service account", True, sh(["create", "-f", "-"], cm("by-other"), OTHER))
        check("not matched: Argo in an unprotected namespace", True, sh(["create", "-f", "-"], cm("anything", None, ns="open"), ARGO))
        check("not matched: a cluster-scoped Namespace labelled protected (scope: Namespaced)", True,
              sh(["create", "-f", "-"], {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": "prot2", "labels": {"clearance.hangar.io/protected": "true"}}}, ARGO))
        check("not matched: the scale subresource as Argo", True,
              sh(["patch", "deployment", "web", "-n", "prot", "--subresource=scale", "--type=merge", "-p", '{"spec":{"replicas":2}}'], who=ARGO))

        print(f"-- the injected PreSync wait Job, exactly as the CMP builds it ({mode})")
        check("admit: the Job exactly as the CMP builds it, no stamp, no grant entry", True,
              sh(["create", "-f", "-"], wait_job("wait-ok"), ARGO))
        cases = [
            ("another image", dict(image="busybox")),
            ("an extra --url style flag in args", dict(args=["--change", "ch-1", "--timeout", "1h", "--url", "http://evil"])),
            ("a different args shape", dict(args=["--url", "http://evil", "--timeout", "1h", "--change", "ch-1"])),
            ("CLEARANCE_URL pointed elsewhere (the token would leak)",
             dict(env=[{"name": "CLEARANCE_URL", "value": "http://evil.example"},
                       {"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"}])),
            ("an extra env var", dict(env=[{"name": "CLEARANCE_URL", "value": CORE_URL},
                                          {"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"},
                                          {"name": "X", "value": "y"}])),
            ("envFrom", dict(env_from=True)),
            ("a command override", dict(command=["/bin/sh"])),
            ("hostNetwork", dict(host="hostNetwork")),
            ("hostPID", dict(host="hostPID")),
            ("hostIPC", dict(host="hostIPC")),
            ("a privileged container", dict(privileged=True)),
            ("an extra volume", dict(extra_volume=True)),
            ("a token volume for another audience", dict(token="kubernetes.default")),
            ("hostAliases (the pin is none)", dict(aliases=True)),
            ("an init container", dict(init=True)),
            ("a livenessProbe", dict(ctr={"livenessProbe": {"exec": {"command": ["true"]}}})),
            ("a readinessProbe", dict(ctr={"readinessProbe": {"exec": {"command": ["true"]}}})),
            ("a startupProbe", dict(ctr={"startupProbe": {"exec": {"command": ["true"]}}})),
            ("a lifecycle hook", dict(ctr={"lifecycle": {"preStop": {"exec": {"command": ["true"]}}}})),
            ("a serviceAccountName", dict(pod={"serviceAccountName": "default"})),
            ("the deprecated serviceAccount field", dict(pod={"serviceAccount": "default"})),
            ("a dnsPolicy other than the default", dict(pod={"dnsPolicy": "Default"})),
            ("another schedulerName", dict(pod={"schedulerName": "evil"})),
            ("parallelism 5", dict(job={"parallelism": 5, "completions": 5})),
            ("a dnsConfig", dict(pod={"dnsConfig": {"nameservers": ["10.9.9.9"]}})),
            ("automountServiceAccountToken true", dict(automount=True)),
            ("automountServiceAccountToken unset", dict(automount=None)),
            ("a nodeName", dict(pod={"nodeName": "somewhere"})),
            ("tolerations", dict(pod={"tolerations": [{"operator": "Exists"}]})),
            ("a container workingDir", dict(ctr={"workingDir": "/"})),
            ("container ports", dict(ctr={"ports": [{"containerPort": 80}]})),
            ("an added capability", dict(ctr={"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}})),
            ("allowPrivilegeEscalation true", dict(ctr={"securityContext": {"allowPrivilegeEscalation": True}})),
            ("a subPath on the token mount", dict(ctr={"volumeMounts": [{"name": "clearance-token", "mountPath": "/var/run/secrets/tokens", "subPath": "x"}]})),
            ("a mount of the token elsewhere", dict(ctr={"volumeMounts": [{"name": "clearance-token", "mountPath": "/etc", "readOnly": True}]})),
            ("runAsUser 0", dict(pod={"securityContext": {"runAsNonRoot": False, "runAsUser": 0, "runAsGroup": 65532,
                                                          "seccompProfile": {"type": "RuntimeDefault"}}})),
            ("runAsNonRoot false", dict(pod={"securityContext": {"runAsNonRoot": False, "runAsUser": 65532, "runAsGroup": 65532,
                                                                "seccompProfile": {"type": "RuntimeDefault"}}})),
            ("another runAsUser", dict(pod={"securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 65532,
                                                               "seccompProfile": {"type": "RuntimeDefault"}}})),
            ("seccomp Unconfined", dict(pod={"securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                                                "seccompProfile": {"type": "Unconfined"}}})),
            ("no pod securityContext values", dict(pod={"securityContext": {}})),
            ("a writable root filesystem", dict(ctr={"securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": False,
                                                                      "capabilities": {"drop": ["ALL"]}}})),
            ("capabilities not dropped", dict(ctr={"securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                                    "capabilities": {"drop": ["NET_RAW"]}}})),
            ("no container securityContext", dict(ctr={"securityContext": {}})),
            ("allowPrivilegeEscalation unset", dict(ctr={"securityContext": {"readOnlyRootFilesystem": True,
                                                                          "capabilities": {"drop": ["ALL"]}}})),
            ("a pod sysctl", dict(pod={"securityContext": {"sysctls": [{"name": "net.ipv4.ip_forward", "value": "1"}]}})),
            ("an extra Job field (ttlSecondsAfterFinished)", dict(job={"ttlSecondsAfterFinished": 1})),
            ("the label with another value", dict(label="x")),
            ("no label", dict(label=None)),
            ("no PreSync hook annotation", dict(hook="Sync")),
        ]
        for i, (what, kw) in enumerate(cases):
            check("refuse: the labelled Job with " + what, False, sh(["create", "-f", "-"], wait_job(f"wait-bad{i}", **kw), ARGO),
                  "clearance-protected-writes" if deny else None)
        check("not matched: the same Job with another image by another writer", True,
              sh(["create", "-f", "-"], wait_job("wait-other", image="busybox"), OTHER))

        print(f"-- expiry is the agent's: status.valid ({mode})")
        check("the agent marks the grant expired", True, sh(["patch", "clearancegrant", "g1", "-n", "prot", "--subresource=status",
              "--type=merge", "-p", '{"status":{"valid":false,"reason":"expired"}}'], who=AGENT))
        check("refuse: a listed object under an expired (invalid) grant", False,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v3"}}'], who=ARGO),
              "is not valid")
        check("the agent clears status altogether (never verified)", True, sh(["patch", "clearancegrant", "g1", "-n", "prot",
              "--subresource=status", "--type=json", "-p", '[{"op":"remove","path":"/status/valid"}]'], who=AGENT))
        check("refuse: a grant with no status.valid (has() guard on status)", False,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v4"}}'], who=ARGO), "is not valid")
        sh(["patch", "clearancegrant", "g1", "-n", "prot", "--subresource=status", "--type=merge", "-p", '{"status":{"valid":true}}'], who=AGENT)

        print(f"-- one active grant per namespace; no active grant ({mode})")
        sh(["create", "-f", "-"], grant("g2", {"/ConfigMap/other": H1}), AGENT)
        sh(["patch", "clearancegrant", "g2", "-n", "prot", "--subresource=status", "--type=merge", "-p", '{"status":{"valid":true}}'], who=AGENT)
        check("refuse: two active grants, each must pass (the object is in one only)", False,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v5"}}'], who=ARGO), "does not list")
        sh(["label", "clearancegrant", "g2", "-n", "prot", "clearance.hangar.io/active-"], who=AGENT)
        check("admit again once the agent leaves one active grant", True,
              sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v6"}}'], who=ARGO))
        sh(["label", "clearancegrant", "g1", "-n", "prot", "clearance.hangar.io/active-"], who=AGENT)
        # Deny: a missing param is a binding error and refuses; Warn: parameterNotFoundAction Allow admits, silently.
        r = sh(["create", "-f", "-"], cm("no-grant", H3), ARGO)
        results.append(r[0] == (not deny))
        print(("PASS " if r[0] == (not deny) else "FAIL ") +
              f"[{mode}] no active grant: {'refused (parameterNotFoundAction Deny)' if deny else 'admitted (parameterNotFoundAction Allow)'}"
              + ("" if r[0] == (not deny) else "\n     " + r[1][:300]))

        r = sh(["create", "-f", "-"], cm("by-other-2"), OTHER)
        results.append(r[0] == (not deny))
        print(("PASS " if r[0] == (not deny) else "FAIL ") +
              f"[{mode}] no active grant, another writer: {'refused too (the param resolves before matchConditions)' if deny else 'admitted'}")
        r = sh(["create", "-f", "-"], grant("g3", {}), AGENT)
        results.append(r[0])
        print(("PASS " if r[0] else "FAIL ") + f"[{mode}] no active grant: the agent can still create a grant (excluded from the policy)")
        sh(["delete", "clearancegrant", "g3", "-n", "prot"])

        print(f"-- audit annotation names the grant checked ({mode})")
        sh(["label", "clearancegrant", "g1", "-n", "prot", "clearance.hangar.io/active=true"], who=AGENT)
        sh(["patch", "configmap", "app-cm", "-n", "prot", "--type=merge", "-p", '{"data":{"k":"v7"}}'], who=ARGO)
        time.sleep(1)
        found = False
        if k.audit.exists():
            for line in k.audit.read_text().splitlines():
                if '"clearance-protected-writes' in line and "/grant" in line:
                    ev = json.loads(line)
                    found = found or any(v == "g1" for kk, v in ev.get("annotations", {}).items() if kk.endswith("/grant"))
        results.append(found)
        print(("PASS " if found else "FAIL ") + f"[{mode}] audit annotation grant=g1 in the audit log")

    results.append(not cel_errors)
    print(("PASS " if not cel_errors else "FAIL ") + f"[{mode}] no CEL evaluation error in any response" + ("" if not cel_errors else "\n" + cel_errors[0]))
    return results


def main():
    if not os.environ.get("KUBEBUILDER_ASSETS"):
        if os.environ.get("CI") == "true":  # a green CI run must have tested something
            print("FAIL: KUBEBUILDER_ASSETS is not set under CI=true")
            return 1
        print("skipped: KUBEBUILDER_ASSETS is not set (setup-envtest use 1.36.2 -p path)")
        return 0
    results = run(deny=True) + run(deny=False)
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
