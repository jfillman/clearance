"""Print one version's section of CHANGELOG.md, the GitHub Release's notes (.github/workflows/release.yaml).

    python3 tools/release_notes.py 0.26.1 [CHANGELOG.md]

Exits 1, naming the version, when the changelog has no `## [X.Y.Z] - date` section for it, so a tag cut without
its notes fails the release instead of publishing an empty one."""
import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str | None:
    lines, out, inside = text.splitlines(), [], False
    head = re.compile(rf"^## \[{re.escape(version)}\](\s|$)")
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = bool(head.match(line))
            continue
        if inside:
            if re.match(r"^\[[^\]]+\]: ", line):   # the link references at the foot
                break
            out.append(line)
    if not inside and not out:
        return None
    body = "\n".join(out).strip()
    return body or None


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    path = Path(argv[2] if len(argv) == 3 else "CHANGELOG.md")
    body = section(path.read_text(), version)
    if body is None:
        print(f"{path} has no section for {version}: add '## [{version}] - YYYY-MM-DD' before tagging v{version}",
              file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
