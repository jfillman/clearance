"""glidepath.live.*, releaseRun, evidence, tests, events and previews: their tiers and argument shapes."""
from clearance.packs.hangar import TOOLS, glidepath_bad_args
from clearance.tiers import Tier

NEW = ("glidepath.live.list", "glidepath.live.watch", "glidepath.live.logs.get", "glidepath.releaseRun.get",
       "glidepath.evidence.get", "glidepath.tests.list", "glidepath.tests.report", "glidepath.events.recent",
       "glidepath.previews.list")


def test_all_reads():
    specs = {t.name: t for t in TOOLS}
    for name in NEW:
        assert specs[name].tier is Tier.T0, name
        assert "app" in specs[name].required_args, name


def test_argument_shapes():
    good = {"app": "gate-api", "pipelinerun": "ci-0-build-l99pk", "timeoutSeconds": 90, "taskRun": "ci-0-build-l99pk-build",
            "container": "step-build", "name": "promote-prod-abcdef01-3f9a1c", "id": "6902a1b2c3d4e5f6a7b8c9d0",
            "image": "ghcr.io/jfillman/gate-api:2.0.6-abc1234", "type": "dev.cdevents.pipelinerun.",
            "since": "2026-10-31T00:00:00Z", "limit": 50}
    assert glidepath_bad_args(good) == 0
    assert glidepath_bad_args({"app": "a", "image": "ghcr.io/o/a@sha256:" + "0" * 64}) == 0
    for bad in ({"timeoutSeconds": 0}, {"timeoutSeconds": 121}, {"timeoutSeconds": "60"}, {"container": "Step_Build"},
                {"name": "ci-0-build-l99pk"}, {"name": "promote-prod/../x"}, {"image": "docker.io/library/nginx"},
                {"image": "ghcr.io/o/a b"}, {"id": "../x"}, {"type": "DEV.cdevents"}, {"since": "a b"}):
        assert glidepath_bad_args({**good, **bad}) == 1, bad
