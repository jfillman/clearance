"""Write the Python reference values the Go pycompat and pyyaml tests check against:

    PYTHONPATH=src .venv/bin/python tools/golden/gen_vectors.py

internal/pycompat/testdata/vectors.json (repr of floats and strings, str.lower, str.strip, json.dumps length and
its sort_keys/separators/ensure_ascii variants, fnmatch.fnmatchcase) and internal/pyyaml/testdata/vectors.json
(repr of yaml.safe_load, or the exception class it raises).
"""
import fnmatch
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]

floats = [1.0, 1e16, 1e-5, 0.0001, 123456789012345.6, -0.0, 1.5, 2.5e-7, 1e22, 0.1, 1e15, 9999999999999998.0, 5e-324]
strings = ["a", "it's", 'say "x"', "both ' \"", "tab\tnl\n", "\x00\x7f\x85", "é\u200b\u3000x", "\U0001f600", "\ud7ff",
           "back\\slash", "\u2028", "\xa0"]
lowers = ["ΑΣ", "ΑΣ Β", "İx", "ΣΑ", "Α.Σ", "ABC", "ÀÉ", "ẞ", "ΑΣ'", "Σ"]
strips = [" a ", "\x1c a\x1f", "\u3000t\u3000", "\u200bx", "\x85y\xa0"]
dumps = [{"a": 1}, {"k": "é" * 3}, {"x": [1, 2.5, None, True]}, {"e": "\U0001f600\x7f"}, {}]
pyval = {"float_repr": [[f, repr(f)] for f in floats], "str_repr": [[s, repr(s)] for s in strings],
         "lower": [[s, s.lower()] for s in lowers], "strip": [[s, s.strip()] for s in strips],
         "dumps_len": [[d, len(json.dumps(d))] for d in dumps]}

# json.dumps(sort_keys=True) with each (ensure_ascii, spaced) pair: the gate's digests and register.canonical.
dumps_sorted = [{"b": [1, 1.5, True, None], "a": "café <&> \u2028\x01\x7f", "z": {}}, {"e": "\U0001f600", "n": 1e16}]
pyval["dumps_sorted"] = [[d, [json.dumps(d, sort_keys=True, ensure_ascii=a, separators=(", ", ": ") if sp else (",", ":"))
                              for a, sp in ((False, False), (True, False), (True, True))]] for d in dumps_sorted]

names = ["a-c", "b", "y", "-", "a/b/c", "a\nb", "aXc", "[", "x", "]", "!", "^", "\\", "é", "user:root", "a.b"]
pats = ["a*c", "a?c", "a[!X]c", "a[a-z-]c", "[z-a]", "[a-cz-x]", "[z-a-]", "[!z-a]", "[", "[]]", "[!]]", "[]-]",
        "[!]", "[^a]", "[\\]", "[a-]", "[-a]", "[é]", "user:*", "*", "**", "a.b", "[[]", "[a&&b]", "[!a-c]"]
pyval["fnmatch"] = [[n, p, fnmatch.fnmatchcase(n, p)] for p in pats for n in names]

docs = ["a: yes", "a: 010", "a: 1:20", "a: 0x1F", "a: 1_000", "a: 1e3", "a: 1.e+3", "a: 2024-01-01",
        "a: 2001-12-14t21:59:43.10-05:00", "a: 2001-12-14 21:59:43.10 Z", "a: .inf", "a: -.Inf", "a: ~", "a: y",
        "a: 0b101", "a: -1:30.5", "a: 9223372036854775808", "a: 08", "a: +.5", "a: '1'", "a: !!str 1", "a: !!int '7'",
        "a: [1, {b: on}]", "a: =", "a: !foo x", "? [1]\n: x", "x: 1\n---\ny: 2", "", "a:", "a: 1\na: 2",
        "b: &x {c: 1}\nm:\n  <<: *x\n  d: 2", "m:\n  <<: [{a: 1}, {a: 2, b: 3}]\n  c: 4", ": [", "a: 2024-02-30",
        "a: 1.5e+3", "a: 0o17", "a: 12:30:00", "a: Null", "a: NULL", "a: nULL", "on: push", "1: x\ntrue: y",
        "a: ._1", "a: ! 123", "a: ! [1]", "a: ! {b: 1}", "a: !!bool foo", "a: 2024-01-01 25:00:00", "a: !!float 1",
        "a: 2001-12-14 21:59:43.123456789+05:30"]


def outcome(text):
    try:
        return {"repr": repr(yaml.safe_load(text))}
    except yaml.YAMLError:
        return {"error": "YAMLError"}
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__}


for path, doc in ((ROOT / "internal/pycompat/testdata/vectors.json", pyval),
                  (ROOT / "internal/pyyaml/testdata/vectors.json", [[d, outcome(d)] for d in docs])):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=True) + "\n")
    print("wrote", path.relative_to(ROOT))
