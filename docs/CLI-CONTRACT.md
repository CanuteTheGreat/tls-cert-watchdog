# CLI contract (Errant Solutions free tools, contract version 1)

All Errant Solutions command-line tools follow the same contract, so they can be dropped
into CI pipelines and cron jobs the same way.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean: nothing at or above the failure threshold (or, for a verifier, the check passed). |
| 1 | Findings: at least one finding at or above the failure threshold (or the check failed). |
| 2 | Usage or input error: bad or missing arguments, a file that does not exist or cannot be read or parsed. |
| 3 | Runtime or network error: a target could not be reached, a DNS/API call failed, a required system tool is missing. |

A tool that documented a different code for one of these cases before the contract existed keeps
that code, so scripts do not break. Such differences are listed in the tool's own README under
"Exit codes" (marked "legacy").

## Output

- `--json` writes exactly one JSON document to stdout and nothing else. The top level is an
  object with these keys, always present: `schema_version` (integer, currently `1`), `tool`
  (the command name), `version` (the tool's own version) and `exit_code` (the code the process
  will exit with). Everything else is tool-specific and only ever gains new keys within one
  `schema_version`; a removed or renamed key bumps `schema_version`.
- `--quiet` / `-q` writes nothing to stdout (no report, no JSON); only the exit code and any
  errors on stderr remain. Files requested explicitly (for example `--html FILE`) are still
  written.
- Errors and warnings go to stderr, never to stdout, also with `--json`.
- The JSON Schema for each tool's `--json` output is `schema/<tool>.schema.json` in the
  repository, and is checked by the test suite on every push.

## tls-cert-watchdog

| Code | Meaning here |
|------|--------------|
| 0 | No finding at or above `--fail-on` (default `high`) on any host. |
| 1 | At least one such finding (expired, expiring soon, untrusted, legacy protocol accepted, weak cipher/signature/key...). Legacy, kept so existing scripts keep working: an unreachable host is reported as a HIGH finding ("Connection failed") and so gives exit 1, not 3. |
| 2 | Usage error, or a `--file` that cannot be read, or an unparseable target. |
| 3 | Unexpected runtime error (a bug; never a traceback with exit 1). |

`--json` top-level keys: `schema_version`, `tool`, `version`, `exit_code` and `results` (one entry per host:
`host`, `port`, `starttls`, `findings`, `ok`, ...). Before 2.0.0 the top level was the `results` list itself.

```
$ tls-cert-watchdog example.com --json
{"schema_version": 1, "tool": "tls-cert-watchdog", "version": "2.0.0", "exit_code": 0, "results": [...]}
$ tls-cert-watchdog example.com --quiet; echo $?
1
```
