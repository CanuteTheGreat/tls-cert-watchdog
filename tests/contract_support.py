"""Shared helpers for the CLI-contract tests (identical copy in every Errant tool repo; Python 3.7+, stdlib only).

run_cli(cli_module_path, args, env=None, stdin=None) -> (returncode, stdout, stderr)
validate(instance, schema) -> list of error strings (empty = valid); supports the JSON Schema subset the
schema/<tool>.schema.json files use: type, required, properties, items, enum, const, minimum, anyOf,
additionalProperties (bool only).
"""
import json
import os
import subprocess
import sys

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "null": type(None),
}


def run_cli(script, args, env=None, stdin=None, timeout=60):
    e = dict(os.environ)
    e["PYTHONIOENCODING"] = "utf-8"
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, script] + list(args), input=stdin, env=e, timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def _is(value, t):
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def validate(inst, schema, path="$"):
    errs = []
    if "anyOf" in schema:
        if not any(not validate(inst, s, path) for s in schema["anyOf"]):
            errs.append("%s: matches none of anyOf" % path)
        return errs
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        if not any(_is(inst, x) for x in ts):
            return ["%s: expected %s, got %s" % (path, "/".join(ts), type(inst).__name__)]
    if "const" in schema and inst != schema["const"]:
        errs.append("%s: expected %r, got %r" % (path, schema["const"], inst))
    if "enum" in schema and inst not in schema["enum"]:
        errs.append("%s: %r not in %r" % (path, inst, schema["enum"]))
    if "minimum" in schema and isinstance(inst, (int, float)) and inst < schema["minimum"]:
        errs.append("%s: %r below minimum %r" % (path, inst, schema["minimum"]))
    if isinstance(inst, dict):
        for k in schema.get("required", []):
            if k not in inst:
                errs.append("%s: missing required key %r" % (path, k))
        props = schema.get("properties", {})
        for k, v in inst.items():
            if k in props:
                errs.extend(validate(v, props[k], "%s.%s" % (path, k)))
            elif schema.get("additionalProperties") is False:
                errs.append("%s: unexpected key %r" % (path, k))
    if isinstance(inst, list) and "items" in schema:
        for i, v in enumerate(inst):
            errs.extend(validate(v, schema["items"], "%s[%d]" % (path, i)))
    return errs


def load_schema(root, tool):
    with open(os.path.join(root, "schema", tool + ".schema.json")) as f:
        return json.load(f)
