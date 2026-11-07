import hashlib, json, sys, yaml
def docs(path):
    out = []
    for d in yaml.safe_load_all(open(path)):
        if isinstance(d, dict) and d.get("kind") and isinstance(d.get("metadata"), dict):
            out.append(d)
    return out
def key(d):
    m = d["metadata"]
    return (d.get("apiVersion", ""), d["kind"], m.get("namespace") or "", m.get("name", ""))
def digest(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
head = {key(d): d for d in docs(sys.argv[1])}
tree = hashlib.sha256("\n".join(sorted(f"{'/'.join(k)}:{digest(d)}" for k, d in head.items())).encode()).hexdigest()
print(json.dumps({"tree": tree, "objects": {"/".join(k): digest(d) for k, d in sorted(head.items())}}, indent=1, sort_keys=True))
