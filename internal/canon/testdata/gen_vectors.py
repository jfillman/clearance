"""Generate vectors.jsonl: JSON texts and what the Python core's canonical() makes of them.

Run once (python3 gen_vectors.py > vectors.jsonl) and commit the output; the Go test reads it and never runs
Python. Each line is {"in": <json text>, "out": <canonical text> | null, "go_rejects": bool}: out is null when
json.loads or canonical raises; go_rejects marks inputs Python accepts and canon.Parse refuses on purpose
(NaN/Infinity tokens, which are not JSON and which Postgres jsonb refuses).

canonical() below is audit.py's, copied so this script runs without the package installed.
"""
import json
import random
import sys


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


rng = random.Random(20261102)

INTERESTING_CHARS = [
    "\x00", "\x01", "\x07", "\x08", "\t", "\n", "\x0b", "\x0c", "\r", "\x1f", " ", '"', "\\", "/", "<", ">", "&",
    "'", "\x7f", "\x80", "\x9f", "\xa0", "\xe9", "ÿ", "Ā", " ", " ", "​", "퟿",
    "", "﻿", "�", "￿", "\U00010000", "\U0001f600", "\U0010ffff", "a", "Z", "0", "~",
]

INTERESTING_NUMBERS = [
    "0", "-0", "1", "-1", "0.0", "-0.0", "1.0", "1.50", "0.1", "0.2", "0.30000000000000004", "1e5", "1E5",
    "1e+5", "1e-5", "1E-05", "1e-4", "0.0001", "0.00001", "1e16", "1e+16", "9999999999999998", "9999999999999998.0",
    "1e15", "123456789012345678", "123456789012345678.0", "1.7976931348623157e308", "1e308", "1e309", "1e400",
    "-1e400", "1e-400", "-1e-400", "5e-324", "2.5e-324", "2.4e-324", "4.9406564584124654e-324", "2.2250738585072014e-308",
    "9007199254740993", "9007199254740993.0", "18446744073709551616", "-9223372036854775809", "1.0e0", "100e-2",
    "0e0", "-0e-0", "0.000001", "1.5e300", "3.14159", "12345678901234567890.123", "1" + "0" * 30,
    "0." + "1" * 40, "1" * 40 + ".5",
]
# Emitted once each, not drawn by the random generator (they would bloat the file).
HUGE_NUMBERS = ["9" * 4300, "-" + "9" * 4300, "9" * 4301, "-" + "9" * 4301, "0." + "1" * 400, "1" * 400 + ".5"]


def rand_string():
    n = rng.choice([0, 1, 2, 3, 5, 8, 16])
    return "".join(rng.choice(INTERESTING_CHARS) if rng.random() < 0.5 else chr(rng.randint(0x20, 0x7e))
                   for _ in range(n))


def rand_value(depth=0):
    r = rng.random()
    if depth > 4 or r < 0.45:
        k = rng.random()
        if k < 0.25:
            return ("num", rng.choice(INTERESTING_NUMBERS))
        if k < 0.4:
            return ("num", repr(rng.choice([rng.uniform(-1e20, 1e20), rng.uniform(-1, 1), rng.random() * 10.0 ** rng.randint(-307, 307), float.fromhex("0x1.%013xp%d" % (rng.getrandbits(52), rng.randint(-1074, 1023))),
                                           float(rng.randint(-10**18, 10**18))])))
        if k < 0.5:
            return ("num", str(rng.randint(-10**25, 10**25)))
        if k < 0.85:
            return ("str", rand_string())
        return ("lit", rng.choice(["true", "false", "null"]))
    if r < 0.7:
        return ("arr", [rand_value(depth + 1) for _ in range(rng.randint(0, 5))])
    return ("obj", [(rand_string(), rand_value(depth + 1)) for _ in range(rng.randint(0, 5))])


def ws():
    return rng.choice(["", "", "", " ", "\n", "\t", " \r\n "])


def enc_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(rng.choice(["\\u%04x" % o, "\\u%04X" % o] + ({8: ["\\b"], 9: ["\\t"], 10: ["\\n"], 12: ["\\f"], 13: ["\\r"]}.get(o, []))))
        elif rng.random() < 0.2:
            if o > 0xffff:
                v = o - 0x10000
                out.append("\\u%04x\\u%04x" % (0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)))
            else:
                out.append(rng.choice(["\\u%04x", "\\u%04X"]) % o)
        elif ch == "/" and rng.random() < 0.5:
            out.append("\\/")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def enc(v):
    kind, x = v
    if kind in ("num", "lit"):
        return x
    if kind == "str":
        return enc_string(x)
    if kind == "arr":
        return "[" + ws() + ("," + ws()).join(enc(e) + ws() for e in x) + "]"
    return "{" + ws() + ",".join(ws() + enc_string(k) + ws() + ":" + ws() + enc(e) + ws() for k, e in x) + "}"


EDGE_TEXTS = [
    '{"￿":1,"\U00010000":2,"":3,"퟿":4}',
    '{"b":1,"a":2,"B":3,"aa":4,"":5,"é":6,"é":7}',
    '{"a":1,"a":2}',
    '"\\ud83d\\ude00"', '"\\ud83d"', '"\\ude00"', '"\\ud83dx"', '"\\ud83d\\u0041"', '"\\udbff\\udfff"',
    '"  \x7f<>&"', '"\\u2028"', '"\\u0000"', '"\\u001f\\u007f\\u0080"',
    'NaN', '-Infinity', 'Infinity', '[NaN]', '{"x":Infinity}',
    '"﻿"', '﻿1', '1 ', ' [ ] ', '{}', '[]', '""', 'null', 'true', 'false',
    '[1,]', '{"a":1,}', '01', '1.', '.5', '-', '+1', '1e', '"\t"', "'a'", '[1 2]', '"\\x41"', '"\\U0041"',
    "[" * 400 + "]" * 400,
    '{"seq":0,"hash":"x","verified":["a","b"],"f":1.0,"g":[1e-7,2e21,-0.0]}',
]


def emit(text, out):
    go_rejects = any(t in text for t in ("NaN", "Infinity"))
    try:
        val = json.loads(text)
        c = canonical(val).decode()
    except (ValueError, UnicodeEncodeError, RecursionError):
        c = None
    out.write(json.dumps({"in": text, "out": c, "go_rejects": go_rejects}, ensure_ascii=True) + "\n")


def main():
    out = sys.stdout
    for t in EDGE_TEXTS:
        emit(t, out)
    for n in INTERESTING_NUMBERS + HUGE_NUMBERS:
        emit(n, out)
        emit("[" + n + "]", out)
    for ch in INTERESTING_CHARS:
        emit(enc_string(ch), out)
        emit(json.dumps({ch: ch}, ensure_ascii=False), out)
    for _ in range(3000):
        emit(enc(rand_value()), out)


if __name__ == "__main__":
    main()
