"""Load the live chain dump into a scratch DB and record Python api.py's answers to a list of requests.

usage: golden_py.py ADMIN_DSN CHAIN_JSONL REPO_ROOT OUT_JSON
Writes OUT_JSON: {"dsn": <db dsn>, "answers": [{"path", "token", "who", "status", "body"}]}.
"""
import json
import sys
from pathlib import Path
from urllib.parse import quote

import psycopg

admin, chain, root, out = sys.argv[1:5]
sys.path.insert(0, str(Path(root) / "src"))
from starlette.testclient import TestClient  # noqa: E402

from clearance import api, gate, profile  # noqa: E402
from clearance.dispatch import AuthError, Principal  # noqa: E402
from clearance.packs.hangar import HANGAR  # noqa: E402
from clearance.pg import SCHEMA  # noqa: E402
from clearance.policy import Policy  # noqa: E402
from clearance.tiers import Tier  # noqa: E402

DB = "clr_golden"
with psycopg.connect(admin, autocommit=True) as c:
    c.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    c.execute(f"CREATE DATABASE {DB}")
dsn = admin.rsplit("/", 1)[0] + "/" + DB + ("?" + admin.split("?", 1)[1] if "?" in admin else "")

lines = [l for l in Path(chain).read_text().splitlines() if l.strip()]
recs = [json.loads(l) for l in lines]
with psycopg.connect(dsn, autocommit=True) as c:
    c.execute(SCHEMA)
    for l, r in zip(lines, recs):
        c.execute("INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES (%s, %s, %s, %s::jsonb)",
                  (r["seq"], r["hash"], r["prev_hash"], l))
    # The gateway's sessions, as it wrote them: one row per opened session, its principal the opener's.
    seen = set()
    for r in recs:
        if r["tool"] == "session.open" and r.get("session") and r["session"] not in seen:
            seen.add(r["session"])
            c.execute("INSERT INTO clearance_sessions (id, record, expires_at, closed) VALUES (%s, %s, now(), true)",
                      (r["session"], json.dumps({"id": r["session"], "principal": r["principal"], "agent": r["agent"],
                                                  "task_id": r["task_id"], "created_at": r["ts"]})))

TOWER = "hangar-prod/app-backstage-prod/backstage-ingestor"


class Auth:
    t = {"audit": Principal("user:auditor", "user", Tier.T1), "jf": Principal("user:jfillman", "user", Tier.T1),
         "bob": Principal("user:bob", "user", Tier.T1), "tower": Principal(TOWER, "workload", Tier.T1)}

    def authenticate(self, token):
        if token not in self.t:
            raise AuthError("no")
        return self.t[token]


class Groups:
    def groups(self, p):
        return {"group:default/platform"} if p == "user:bob" else set()


class Owns:
    def apps(self, p):
        return {"gate-api"} if p == "user:jfillman" else set()


defs = profile.load_dir(Path(root) / "tests" / "fixtures" / "agents")
access = api.Access(Auth(), defs, delegates=(TOWER,), notifiers=(TOWER,), auditors=("user:auditor",),
                    directory=Groups(), ownership=Owns())
store = api.PgReadStore(api.Pool(dsn, size=2))
app = api.create_api_app(store, access, policy=Policy((HANGAR,)), gate_policy=gate.GatePolicy())

viewers = [("audit", None), ("jf", None), ("tower", "user:jfillman"), ("bob", None)]
paths = []
for f in ["", "decision=deny", "tool=provenance.verify", "agent=triage-agent", "app=gate-api", "rule=R007",
          "since=2026-10-30T00:00:00Z", "until=2026-10-30T00:00:00Z", "since=2026-10-30T00:00:00.000Z&until=2026-11-01T00:00:00Z",
          "principal=user:jfillman", "tool=model.call&decision=allow", "task=" + recs[100]["task_id"],
          "session=" + str(recs[100]["session"]), "limit=7", "limit=200", "limit=0", "after=300", "after=300&limit=13"]:
    paths.append("/v1/evidence" + ("?" + f if f else ""))
for by in ["rule", "tool", "agent", "app", "decision"]:
    for f in ["", "&decision=deny", "&agent=triage-agent", "&tool=repo.file.get", "&app=gate-api",
              "&since=2026-10-31T00:00:00Z", "&until=2026-10-31T00:00:00Z"]:
        paths.append(f"/v1/evidence/counts?by={by}{f}")
paths.append("/v1/evidence/counts")
for seq in [0, 1, 100, 250, 400, 611, 612]:
    paths.append(f"/v1/evidence/{seq}")
paths.append("/v1/evidence/verify")
repos = sorted({(r.get("effect") or {}).get("repo") for r in recs if r.get("effect")} |
               {r["target"].split("#")[0] for r in recs if r["tool"] == "provenance.verify" and r.get("target")})
for repo in repos[:6]:
    paths += [f"/v1/receipts?repo={repo}", f"/v1/provenance?repo={repo}"]
for r in recs:
    if r.get("effect"):
        paths.append(f"/v1/receipts?repo={r['effect']['repo']}&pr={r['effect']['pr']}")
for r in [x for x in recs if x["tool"] == "provenance.verify"][:5]:
    repo, pr = r["target"].split("@")[0].split("#")
    paths.append(f"/v1/provenance?repo={repo}&pr={pr}")
paths += ["/v1/policy", "/v1/clearance-policy", "/v1/clearances", "/v1/clearances/counts?by=state"]
for agent, tool, args in [("coding-agent", "metrics.query", {"promql": "up"}),
                          ("orchestrator", "repo.pr.open", {"repo": "jfillman/x", "branch": "b", "title": "t", "files": [{"path": "a", "content": "c"}]}),
                          ("triage-agent", "repo.pr.open", {"repo": "jfillman/gitops-gate-api", "branch": "b", "title": "t", "files": [{"path": ".tekton/x.yaml", "content": "c"}]}),
                          ("triage-agent", "k8s.exec", {}), ("coding-agent", "no.such.tool", {}),
                          ("nightly-reviewer", "glidepath.run.rerun", {"app": "gate-api", "run": "r-1"})]:
    paths.append(f"/v1/policy/explain?agent={agent}&tool={tool}&args={quote(json.dumps(args))}")

answers = []
with TestClient(app) as c:
    for p in paths:
        for tok, who in viewers:
            h = {"Authorization": f"Bearer {tok}"}
            if who:
                h["X-Hangar-On-Behalf-Of"] = who
            r = c.get(p, headers=h)
            answers.append({"path": p, "token": tok, "who": who, "status": r.status_code, "body": r.json()})
Path(out).write_text(json.dumps({"dsn": dsn, "answers": answers}))
print(f"{len(answers)} answers, db {DB}")
