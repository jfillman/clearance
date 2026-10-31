"""The deployment gate (Clearances), phase 1: may this change land in a protected environment?

docs/gate.md is the design (decided 2026-10-31). The runtime boundary decides tool calls; this module decides
changes. A **change** is a commit to a gitops repo that Argo CD would sync to a protected environment, described by
the CI check that registers it (glidepath's `clearance-gate-`): the PR, its head, the rendered manifest tree's digest,
and the objects the diff touches with the fields that changed. Clearance never renders anything itself; it classifies
what the verifier describes, and every description is recorded as claimed, the decision as verified.

A change gets a **tier**, 0 to 3, the maximum over everything it touches, from a baseline this module owns
(`GatePolicy`) that a repo's `clearance.yaml` may only tighten:
  0  nothing a cluster runs: documentation, tests, label or annotation only
  1  an image bump on a Flight-registry image, with CI green, provenance confirmed and the render clean
  2  runtime shape: replicas, resources, a Rollout's strategy, config, network, routes, probes, unknown kinds
  3  Secrets and anything that reaches one, identity and RBAC, AppProjects, jobs that write data, policy itself
Tiers 0 and 1 are **cleared by policy** at once. Tier 2 waits for one person from the app's owner group; tier 3 for
one from the owner group and one from an outside group (admins), neither the proposer, never the same person twice.
A change not cleared within its TTL (7 days) expires; a new head on the same PR supersedes the old one. Each step is an
evidence record in the deployment boundary: `deploy.request`, `deploy.clear`, `deploy.deny`, `deploy.expire`.

Nothing here enforces: phase 1 is the soft gate (the check's status, Tower, the release guardrail). Phase 2 publishes
cleared grants for the protected cluster to pull (gate.md, "A without a remote write").
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Any, Iterable, Mapping, Protocol, Sequence

DEFAULT_TTL_DAYS = 7
MAX_TTL_DAYS = 30
MAX_OBJECTS = 2000
MAX_PATHS = 4000
MAX_FIELDS = 400
MAX_REASON = 500
MAX_LINES_TIER1 = 400
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
GROUP = re.compile(r"^group:[a-z0-9-]+/[a-z0-9._-]+$")
PRINCIPAL = re.compile(r"^[A-Za-z0-9:/_.@\[\]-]{1,200}$")
STATES = ("holding", "cleared", "denied", "expired", "superseded")
PROPOSER_KINDS = ("person", "agent", "unknown")
OPS = ("added", "changed", "removed")
# What each check must say for policy to clear a tier-1 change.
CHECKS_OK: dict[str, tuple[str, ...]] = {"ci": ("pass",), "provenance": ("confirmed", "not-agent"), "render": ("ok",)}
IMAGE_FIELD = re.compile(r"^/spec/(template/spec/|jobTemplate/spec/template/spec/)?(init)?[cC]ontainers/\d+/image$")
METADATA_ONLY = ("/metadata/labels", "/metadata/annotations")


class GateError(Exception):
    """A refusal the caller can act on: `rule` (DG-*), `message`, `hint`; `status` is the HTTP status."""
    def __init__(self, rule: str, message: str, hint: str = "", status: int = 400):
        self.rule, self.message, self.hint, self.status = rule, message, hint, status
        super().__init__(message)


class BadChange(ValueError):
    """The verifier's description of a change is malformed (400)."""


# -- the baseline, and how a repo tightens it ----------------------------------------------------------------------
@dataclass(frozen=True)
class GatePolicy:
    """The platform's tier table and approval rule. A repo's clearance.yaml may add kinds, paths and field tokens to
    tiers 2 and 3, raise the people required, and shorten the TTL; nothing else (`tightened`)."""
    version: str = "baseline-2026-10-31"
    tier3_kinds: frozenset[str] = frozenset({
        "Secret", "ExternalSecret", "SecretStore", "ClusterSecretStore", "ClusterExternalSecret", "PushSecret",
        "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "AppProject",
        "Job", "CronJob", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingPolicy",
        "ClusterPolicy", "Policy", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    })
    # Changed-field tokens that reach a secret, an identity or a privilege, whatever the kind.
    tier3_fields: tuple[str, ...] = ("secretKeyRef", "secretRef", "envFrom", "imagePullSecrets", "serviceAccountName",
                                     "serviceAccount", "securityContext", "hostNetwork", "hostPID", "hostIPC",
                                     "privileged", "capabilities", "/secret/", "automountServiceAccountToken")
    tier3_paths: tuple[str, ...] = ("clearance.yaml", "**/clearance.yaml", "**/appproject*.yaml", "**/AppProject*.yaml")
    # Paths that never run on a cluster; a change touching only these, with no object changed, is tier 0.
    nonruntime_paths: tuple[str, ...] = ("docs/**", "**/*.md", "*.md", "LICENSE", ".gitignore", "tests/**", "**/tests/**",
                                         ".github/**", "CODEOWNERS")
    flight_registries: tuple[str, ...] = ()   # image prefixes a tier-1 bump may come from; empty = any registry
    max_lines_tier1: int = MAX_LINES_TIER1
    outside_groups: tuple[str, ...] = ("group:default/admins",)
    ttl_days: int = DEFAULT_TTL_DAYS
    approvers: Mapping[int, Mapping[str, int]] = field(default_factory=lambda: {2: {"owner": 1, "outside": 0},
                                                                                3: {"owner": 1, "outside": 1}})
    repo_policy_digest: str | None = None   # set by `tightened`: the clearance.yaml that shaped this policy

    def view(self) -> dict[str, Any]:
        return {"version": self.version,
                "tiers": {"3": {"kinds": sorted(self.tier3_kinds), "fields": list(self.tier3_fields), "paths": list(self.tier3_paths)},
                          "0": {"paths": list(self.nonruntime_paths)}},
                "flightRegistries": list(self.flight_registries), "maxLinesTier1": self.max_lines_tier1,
                "outsideGroups": list(self.outside_groups), "ttlDays": self.ttl_days,
                "approvers": {str(t): dict(a) for t, a in sorted(self.approvers.items())},
                "repoPolicy": self.repo_policy_digest}

    def tightened(self, repo_policy: Any) -> "GatePolicy":
        """Apply a repo's clearance.yaml. Allowed: `tiers.3.{kinds,paths,fields}` (add), `tiers.2.{kinds,paths}` (add:
        a kind already tier 3 stays 3), `approvers.{2,3}.{owner,outside}` (raise), `ttlDays` (shorten). Anything that
        loosens, or an unknown key, is refused (DG-POLICY): the file is itself a tier-3 change and never bends the
        baseline."""
        if repo_policy is None:
            return self
        if not isinstance(repo_policy, Mapping):
            raise GateError("DG-POLICY", "clearance.yaml is a mapping", "", 400)
        digest = hashlib.sha256(json.dumps(repo_policy, sort_keys=True, default=str).encode()).hexdigest()
        unknown = set(repo_policy) - {"tiers", "approvers", "ttlDays"}
        if unknown:
            raise GateError("DG-POLICY", f"clearance.yaml: unknown key {sorted(unknown)[0]!r}",
                            "Allowed: tiers.{2,3}.{kinds,paths,fields}, approvers.{2,3}.{owner,outside}, ttlDays.", 400)
        t3k, t3f, t3p = set(self.tier3_kinds), list(self.tier3_fields), list(self.tier3_paths)
        tiers = repo_policy.get("tiers") or {}
        if not isinstance(tiers, Mapping) or set(str(k) for k in tiers) - {"2", "3"}:
            raise GateError("DG-POLICY", "clearance.yaml: tiers names 2 and 3 only (tiers 0 and 1 cannot be widened)", "", 400)
        for t, spec in tiers.items():
            if not isinstance(spec, Mapping) or set(spec) - {"kinds", "paths", "fields"}:
                raise GateError("DG-POLICY", f"clearance.yaml: tiers.{t} takes kinds, paths, fields", "", 400)
            for k in ("kinds", "paths", "fields"):
                v = spec.get(k, [])
                if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
                    raise GateError("DG-POLICY", f"clearance.yaml: tiers.{t}.{k} is a list of strings", "", 400)
            if str(t) == "3":
                t3k |= set(spec.get("kinds", [])); t3f += list(spec.get("fields", [])); t3p += list(spec.get("paths", []))
        # Tier 2 additions only matter for kinds the baseline would call tier 0 (none by kind) and for paths: a
        # path listed under tiers.2 makes a change touching it at least tier 2. Kept as tier2_paths.
        t2p = list(tiers.get("2", {}).get("paths", []) if isinstance(tiers.get("2"), Mapping) else [])
        appr = {t: dict(a) for t, a in self.approvers.items()}
        for t, spec in (repo_policy.get("approvers") or {}).items():
            if str(t) not in ("2", "3") or not isinstance(spec, Mapping) or set(spec) - {"owner", "outside"}:
                raise GateError("DG-POLICY", "clearance.yaml: approvers.{2,3}.{owner,outside} only", "", 400)
            for role, n in spec.items():
                if not isinstance(n, int) or isinstance(n, bool) or n < appr[int(t)][role]:
                    raise GateError("DG-POLICY", f"clearance.yaml: approvers.{t}.{role} may only be raised above {appr[int(t)][role]}", "", 400)
                appr[int(t)][role] = n
        ttl = repo_policy.get("ttlDays", self.ttl_days)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1 or ttl > self.ttl_days:
            raise GateError("DG-POLICY", f"clearance.yaml: ttlDays is 1 to {self.ttl_days} (the baseline; it may only be shortened)", "", 400)
        return GatePolicy(version=self.version, tier3_kinds=frozenset(t3k), tier3_fields=tuple(t3f), tier3_paths=tuple(t3p),
                          nonruntime_paths=self.nonruntime_paths, flight_registries=self.flight_registries,
                          max_lines_tier1=self.max_lines_tier1, outside_groups=self.outside_groups, ttl_days=ttl,
                          approvers=appr, repo_policy_digest=digest, tier2_paths=tuple(t2p))

    tier2_paths: tuple[str, ...] = ()


def _globs(path: str, globs: Iterable[str]) -> bool:
    return any(fnmatchcase(path, g) or (g.startswith("**/") and fnmatchcase(path, g[3:])) for g in globs)


# -- the change as the verifier describes it --------------------------------------------------------------------
@dataclass(frozen=True)
class ObjectChange:
    api_version: str
    kind: str
    namespace: str
    name: str
    op: str                          # added | changed | removed
    fields: tuple[str, ...] = ()     # JSON pointers of the fields that changed (changed only); () = whole object
    images: tuple[str, ...] = ()     # the new container images, when an image field changed
    digest: str = ""                 # sha256 of the normalised object after the change ("" when removed)

    @property
    def subject(self) -> str:
        return f"{self.kind} {self.namespace + '/' if self.namespace else ''}{self.name}"

    def view(self) -> dict[str, Any]:
        return {"apiVersion": self.api_version, "kind": self.kind, "namespace": self.namespace, "name": self.name,
                "op": self.op, "fields": list(self.fields), "images": list(self.images), "digest": self.digest}


@dataclass(frozen=True)
class ChangeRequest:
    app: str
    env: str
    cluster: str
    repo: str
    pr: int
    head: str
    base: str
    proposer: str                    # user:<login>, or the agent's identity
    proposer_kind: str               # person | agent | unknown (the agent gates' identity verdict)
    owner: str                       # the app's owner group (group:<ns>/<name>); "" = the gateway looks it up
    protected: bool
    tree_digest: str
    paths: tuple[str, ...]
    lines_changed: int
    objects: tuple[ObjectChange, ...]
    checks: Mapping[str, str]        # ci, provenance, render, admission: what each says now
    policy: Mapping[str, Any] | None = None   # the repo's clearance.yaml at head, if any
    agent: str | None = None         # the agent that proposed it, when known

    @property
    def id(self) -> str:
        return "ch-" + hashlib.sha256(f"{self.repo}#{self.pr}@{self.head}".encode()).hexdigest()[:16]

    @classmethod
    def from_dict(cls, d: Any) -> "ChangeRequest":
        if not isinstance(d, Mapping):
            raise BadChange("the body is a JSON object")
        def s(k: str, rx: re.Pattern | None = None, required: bool = True, default: str = "") -> str:
            v = d.get(k, default)
            if v in (None, "") and not required:
                return default
            if not isinstance(v, str) or not v or (rx is not None and not rx.match(v)):
                raise BadChange(f"{k} is missing or malformed")
            return v
        app, env, cluster = s("app", NAME), s("env", NAME), s("cluster", NAME)
        repo, head = s("repo", REPO).lower(), s("head", SHA)
        base = s("base", SHA, required=False)
        pr = d.get("pr")
        if not isinstance(pr, int) or isinstance(pr, bool) or pr < 1:
            raise BadChange("pr is a positive integer")
        proposer = s("proposer", PRINCIPAL)
        kind = s("proposerKind", required=False, default="person")
        if kind not in PROPOSER_KINDS:
            raise BadChange("proposerKind is person, agent or unknown")
        owner = s("owner", GROUP, required=False)   # the gateway fills it from the catalog when the check cannot
        protected = d.get("protected", True)
        if not isinstance(protected, bool):
            raise BadChange("protected is a boolean")
        tree = s("treeDigest")
        if not re.match(r"^(sha256:)?[0-9a-f]{64}$", tree):
            raise BadChange("treeDigest is a sha256")
        paths = d.get("paths", [])
        if not isinstance(paths, list) or len(paths) > MAX_PATHS or not all(isinstance(p, str) and p for p in paths):
            raise BadChange(f"paths is a list of at most {MAX_PATHS} strings")
        lines = d.get("linesChanged", 0)
        if not isinstance(lines, int) or isinstance(lines, bool) or lines < 0:
            raise BadChange("linesChanged is a non-negative integer")
        raw_objects = d.get("objects", [])
        if not isinstance(raw_objects, list) or len(raw_objects) > MAX_OBJECTS:
            raise BadChange(f"objects is a list of at most {MAX_OBJECTS}")
        objects = []
        for o in raw_objects:
            if not isinstance(o, Mapping):
                raise BadChange("objects[] are objects")
            op = o.get("op", "changed")
            if op not in OPS:
                raise BadChange("objects[].op is added, changed or removed")
            fields = o.get("fields", [])
            images = o.get("images", [])
            if not isinstance(fields, list) or len(fields) > MAX_FIELDS or not all(isinstance(f, str) and f.startswith("/") for f in fields):
                raise BadChange(f"objects[].fields is a list of at most {MAX_FIELDS} JSON pointers")
            if not isinstance(images, list) or not all(isinstance(i, str) for i in images):
                raise BadChange("objects[].images is a list of strings")
            for k in ("apiVersion", "kind", "name"):
                if not isinstance(o.get(k), str) or not o.get(k):
                    raise BadChange(f"objects[].{k} is required")
            ns = o.get("namespace", "")
            if not isinstance(ns, str):
                raise BadChange("objects[].namespace is a string")
            digest = o.get("digest", "")
            if not isinstance(digest, str):
                raise BadChange("objects[].digest is a string")
            objects.append(ObjectChange(o["apiVersion"], o["kind"], ns, o["name"], op, tuple(fields), tuple(images), digest))
        checks = d.get("checks", {})
        if not isinstance(checks, Mapping) or not all(isinstance(k, str) and isinstance(v, str) for k, v in checks.items()):
            raise BadChange("checks is an object of strings")
        policy = d.get("policy")
        if policy is not None and not isinstance(policy, Mapping):
            raise BadChange("policy (clearance.yaml) is an object")
        agent = d.get("agent")
        if agent is not None and (not isinstance(agent, str) or not NAME.match(agent)):
            raise BadChange("agent is an agent name")
        return cls(app, env, cluster, repo, pr, head, base, proposer, kind, owner, protected, tree, tuple(paths), lines,
                   tuple(objects), dict(checks), dict(policy) if policy is not None else None, agent)


# -- classification ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Reason:
    subject: str     # an object ("Secret ns/name"), a path, or the change itself
    rule: str        # kind:Secret | field:secretKeyRef | path:clearance.yaml | image-bump | image:not-flight-registry |
                     # metadata-only | non-runtime | lines>N | checks:ci,render | provenance:agent | provenance:unknown
    tier: int

    def view(self) -> dict[str, Any]:
        return {"subject": self.subject, "rule": self.rule, "tier": self.tier}


@dataclass(frozen=True)
class Requirement:
    owner: int
    outside: int
    owner_group: str
    outside_groups: tuple[str, ...]

    def view(self) -> dict[str, Any]:
        return {"owner": self.owner, "outside": self.outside, "ownerGroup": self.owner_group,
                "outsideGroups": list(self.outside_groups)}

    def satisfied(self, approvals: Iterable[Mapping[str, Any]]) -> bool:
        roles = [a.get("role") for a in approvals]
        return roles.count("owner") >= self.owner and roles.count("outside") >= self.outside

    def words(self) -> str:
        parts = []
        if self.owner:
            parts.append(f"{self.owner} from {self.owner_group}")
        if self.outside:
            parts.append(f"{self.outside} from outside ({', '.join(self.outside_groups)})")
        return " and ".join(parts) or "nobody"


@dataclass(frozen=True)
class Classification:
    tier: int
    reasons: tuple[Reason, ...]
    decision: str            # clear | hold | deny
    rule: str | None         # the deny rule, when denied
    why: str
    requirement: Requirement | None
    policy: GatePolicy       # the effective (tightened) policy


def _object_tier(ch: ObjectChange, pol: GatePolicy) -> Reason:
    if ch.kind in pol.tier3_kinds:
        return Reason(ch.subject, f"kind:{ch.kind}", 3)
    for f in ch.fields:
        for token in pol.tier3_fields:
            if token in f:
                return Reason(ch.subject, f"field:{token.strip('/')}", 3)
    if ch.op == "changed" and ch.fields:
        if all(f.startswith(METADATA_ONLY) for f in ch.fields):
            return Reason(ch.subject, "metadata-only", 0)
        if all(IMAGE_FIELD.match(f) for f in ch.fields):
            if pol.flight_registries and not all(any(i.startswith(r) for r in pol.flight_registries) for i in ch.images):
                return Reason(ch.subject, "image:not-flight-registry", 2)
            return Reason(ch.subject, "image-bump", 1)
    return Reason(ch.subject, f"kind:{ch.kind}", 2)


def classify(req: ChangeRequest, baseline: GatePolicy) -> Classification:
    """The tier, why, and what follows: cleared by policy, held for people, or denied. Raises GateError (DG-POLICY)
    when the repo's clearance.yaml tries to loosen the baseline."""
    pol = baseline.tightened(req.policy)
    reasons: list[Reason] = []
    for p in req.paths:
        if _globs(p, pol.tier3_paths):
            reasons.append(Reason(p, "path:" + p.rsplit("/", 1)[-1], 3))
        elif _globs(p, pol.tier2_paths):
            reasons.append(Reason(p, "path:tier2", 2))
        elif _globs(p, pol.nonruntime_paths):
            reasons.append(Reason(p, "non-runtime", 0))
    for ch in req.objects:
        reasons.append(_object_tier(ch, pol))
    tier = max((r.tier for r in reasons), default=0)
    if tier == 1 and req.lines_changed > pol.max_lines_tier1:
        reasons.append(Reason("the diff", f"lines>{pol.max_lines_tier1}", 2)); tier = 2
    if req.proposer_kind == "unknown":
        reasons.append(Reason("the PR", "provenance:unknown", 3))
        return Classification(max(tier, 2), tuple(reasons), "deny", "DG-PROVENANCE",
                              "the PR looks like an agent's but Clearance has no record of opening it (the agent gates fail it too)",
                              None, pol)
    if req.proposer_kind == "agent" and tier == 0:
        reasons.append(Reason("the PR", "provenance:agent", 1)); tier = 1
    if tier == 1:
        missing = [c for c, ok in CHECKS_OK.items() if req.checks.get(c) not in ok]
        if missing:
            reasons.append(Reason("the checks", "checks:" + ",".join(missing), 2)); tier = 2
    if tier <= 1:
        return Classification(tier, tuple(reasons), "clear", None, f"tier {tier}: cleared by policy", None, pol)
    a = pol.approvers.get(tier, {"owner": 1, "outside": 1})
    requirement = Requirement(int(a.get("owner", 1)), int(a.get("outside", 0)), req.owner, pol.outside_groups)
    return Classification(tier, tuple(reasons), "hold", None, f"tier {tier}: holding for {requirement.words()}", requirement, pol)


# -- the change on record ----------------------------------------------------------------------------------------
@dataclass
class Change:
    id: str
    app: str
    env: str
    cluster: str
    repo: str
    pr: int
    head: str
    base: str
    proposer: str
    proposer_kind: str
    agent: str | None
    owner: str
    protected: bool
    tree_digest: str
    paths: list[str]
    lines_changed: int
    objects: list[dict[str, Any]]
    checks: dict[str, str]
    policy_version: str
    repo_policy_digest: str | None
    tier: int
    reasons: list[dict[str, Any]]
    requirement: dict[str, Any] | None
    state: str                       # holding | cleared | denied | expired | superseded
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    registered_by: str               # the verifier
    approvals: list[dict[str, Any]] = field(default_factory=list)   # {person, via, role, at}
    cleared_by: str | None = None    # policy | people
    decided_at: datetime | None = None
    deny_reason: str | None = None
    denied_by: str | None = None
    superseded_by: str | None = None

    @property
    def target(self) -> str:
        return f"{self.repo}#{self.pr}@{self.head[:7]}"

    def requirement_obj(self) -> Requirement | None:
        r = self.requirement
        return Requirement(r["owner"], r["outside"], r["ownerGroup"], tuple(r["outsideGroups"])) if r else None

    def view(self, now: datetime | None = None) -> dict[str, Any]:
        d = asdict(self)
        for k in ("created_at", "updated_at", "expires_at", "decided_at"):
            d[k] = d[k].isoformat() if d[k] else None
        d["target"] = self.target
        d["objects_count"] = len(self.objects)
        d["paths_count"] = len(self.paths)
        return d

    def summary(self) -> dict[str, Any]:
        """What a record carries about the change (claimed: the verifier described it)."""
        return {"id": self.id, "app": self.app, "env": self.env, "cluster": self.cluster, "head": self.head,
                "tree": self.tree_digest, "tier": self.tier, "state": self.state, "objects": len(self.objects)}

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> "Change":
        d = {k: v for k, v in r.items() if k not in ("target", "objects_count", "paths_count")}
        for k in ("created_at", "updated_at", "expires_at", "decided_at"):
            d[k] = datetime.fromisoformat(d[k]) if d.get(k) else None
        return cls(**d)

    @classmethod
    def open(cls, req: ChangeRequest, c: Classification, now: datetime, registered_by: str) -> "Change":
        return cls(id=req.id, app=req.app, env=req.env, cluster=req.cluster, repo=req.repo, pr=req.pr, head=req.head,
                   base=req.base, proposer=req.proposer, proposer_kind=req.proposer_kind, agent=req.agent, owner=req.owner,
                   protected=req.protected, tree_digest=req.tree_digest, paths=list(req.paths), lines_changed=req.lines_changed,
                   objects=[o.view() for o in req.objects], checks=dict(req.checks), policy_version=c.policy.version,
                   repo_policy_digest=c.policy.repo_policy_digest, tier=c.tier, reasons=[r.view() for r in c.reasons],
                   requirement=c.requirement.view() if c.requirement else None, state="holding", created_at=now,
                   updated_at=now, expires_at=now + timedelta(days=c.policy.ttl_days), registered_by=registered_by)


class ChangeStore(Protocol):
    def get(self, change_id: str) -> Change | None: ...
    def put(self, c: Change) -> None: ...
    def for_pr(self, repo: str, pr: int) -> list[Change]: ...
    def holding(self, now: datetime) -> list[Change]: ...


class MemoryChanges:
    def __init__(self) -> None:
        self._c: dict[str, Change] = {}

    def get(self, change_id: str) -> Change | None:
        return self._c.get(change_id)

    def put(self, c: Change) -> None:
        self._c[c.id] = c

    def for_pr(self, repo: str, pr: int) -> list[Change]:
        return [c for c in self._c.values() if c.repo == repo and c.pr == pr]

    def holding(self, now: datetime) -> list[Change]:
        return [c for c in self._c.values() if c.state == "holding"]

    def all(self) -> list[Change]:
        return list(self._c.values())


def check_reason(reason: Any) -> str:
    if not isinstance(reason, str) or not reason.strip():
        raise GateError("DG-REASON", "a reason is required", "Say why, in a sentence; it is recorded.", 400)
    if len(reason) > MAX_REASON:
        raise GateError("DG-REASON", f"the reason is longer than {MAX_REASON} characters", "", 400)
    return reason.strip()


def role_for(person: str, groups: Iterable[str], c: Change, admins: Sequence[str] = ()) -> str:
    """Which requirement a person satisfies: `owner` (in the app's owner group) first, else `outside` (in an outside
    group). Raises DG-PROPOSER for the proposer, DG-TWICE for a second approval, DG-FORBIDDEN for everyone else."""
    if c.state != "holding":
        raise GateError("DG-STATE", f"this change is {c.state}", "", 409)
    if person == c.proposer:
        raise GateError("DG-PROPOSER", "the proposer of a change cannot clear it", "Someone else from the owner group must.", 403)
    if any(a.get("person") == person for a in c.approvals):
        raise GateError("DG-TWICE", f"{person} already cleared this change", "A second person is needed.", 409)
    req = c.requirement_obj()
    if req is None:
        raise GateError("DG-STATE", "this change needs no person", "", 409)
    gs = set(groups)
    have = {a.get("role") for a in c.approvals}
    roles = [a.get("role") for a in c.approvals]
    if req.owner_group in gs and roles.count("owner") < req.owner:
        return "owner"
    if any(g in gs for g in req.outside_groups) and roles.count("outside") < req.outside:
        return "outside"
    if req.owner_group in gs or any(g in gs for g in req.outside_groups):
        raise GateError("DG-FILLED", f"the {'owner' if req.owner_group in gs else 'outside'} requirement is already met; "
                        f"this change still needs {req.words()}", "", 409)
    del have
    raise GateError("DG-FORBIDDEN", f"{person} is in neither {req.owner_group} nor an outside group ({', '.join(req.outside_groups)})",
                    "Only the app's owner group and the outside group may clear.", 403)
