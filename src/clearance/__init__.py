"""Clearance: policy, audit and session gateway for AI agent workloads.

The core (everything here but packs/hangar) imports nothing from Hangar; tests/test_boundary.py holds it to that."""
from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("clearance")   # pyproject.toml's version, the one the vX.Y.Z tag names
except PackageNotFoundError:              # imported from a source tree that was never installed
    __version__ = "0.0.0+unknown"
