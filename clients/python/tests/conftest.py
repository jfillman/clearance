"""A real core for the tests: `clearance core --memory --insecure-dev-auth`, built from this checkout with go build.

Only the tests build or run the binary; the library never does. CLEARANCE_BIN names a prebuilt binary instead.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
GW = "autopilot-system/clearance"
CI = "app-gate-api-cicd/pipeline-runner"
PROVIDERS = [{"name": "autopilot-gateway", "version": "0.3.27", "principals": [GW]}]


@pytest.fixture(scope="session")
def clearance_bin(tmp_path_factory) -> str:
    if os.environ.get("CLEARANCE_BIN"):
        return os.environ["CLEARANCE_BIN"]
    go = shutil.which("go")
    if go is None:
        pytest.fail("these tests run a real core: install Go or set CLEARANCE_BIN")
    out = tmp_path_factory.mktemp("bin") / "clearance"
    subprocess.run([go, "build", "-o", str(out), "./cmd/clearance"], cwd=REPO, check=True)
    return str(out)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Core:
    def __init__(self, binary: str):
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLEARANCE_")}
        env.update(CLEARANCE_PROVIDERS=json.dumps(PROVIDERS), CLEARANCE_VERIFIERS="app-*-cicd/pipeline-runner",
                   CLEARANCE_ADMINS="user:admin")
        self.proc = subprocess.Popen(
            [binary, "core", "--memory", "--insecure-dev-auth", "--listen", f"127.0.0.1:{self.port}"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 15
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError("clearance core exited: " + self.proc.stderr.read().decode(errors="replace"))
            try:
                with urllib.request.urlopen(self.url + "/readyz", timeout=0.5) as r:
                    if r.status == 200:
                        return
            except OSError:
                pass
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError("clearance core did not become ready")
            time.sleep(0.05)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stderr.close()


@pytest.fixture
def core(clearance_bin):
    c = Core(clearance_bin)
    yield c
    c.stop()
