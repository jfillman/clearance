"""Release hygiene: the version a tag names is the one the package reports, and CHANGELOG.md says what it shipped
(.github/workflows/release.yaml fails a tag whose section is missing)."""
import re
import tomllib
from pathlib import Path

import clearance

ROOT = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_version_comes_from_the_package_metadata():
    assert clearance.__version__ == VERSION


def test_the_changelog_has_a_section_for_this_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert "## [Unreleased]" in text
    assert re.search(rf"^## \[{re.escape(VERSION)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", text, re.M), \
        f"CHANGELOG.md has no '## [{VERSION}] - <date>' section"


def test_release_notes_extract_one_section():
    import subprocess
    out = subprocess.run(["python3", str(ROOT / "tools" / "release_notes.py"), VERSION, str(ROOT / "CHANGELOG.md")],
                         check=True, capture_output=True, text=True).stdout
    assert out.strip() and "## [" not in out
    missing = subprocess.run(["python3", str(ROOT / "tools" / "release_notes.py"), "999.0.0",
                              str(ROOT / "CHANGELOG.md")], capture_output=True, text=True)
    assert missing.returncode != 0 and "999.0.0" in missing.stderr
