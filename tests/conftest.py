"""pytest hook used ONLY by mutation testing (ci/mutation.sh -> mutmut).

The unittest suite (ci/run-tests.sh) runs the tool exactly as a user does:
`subprocess.run([sys.executable, TOOL, ...])`. mutmut 3 decides which tests
cover which mutant by recording calls inside the test process, so calls that
happen in a child python are invisible to it and every mutant would be
reported as "no tests".

When mutmut is driving the run (MUTANT_UNDER_TEST is set), this file swaps
`subprocess.run` for an in-process equivalent for exactly that one call shape:
it re-imports the (mutated) tool module, runs `main()` with the same argv,
stdin, env and cwd, captures stdout/stderr and returns a CompletedProcess with
the exit status `sys.exit(main())` would have produced. Every other subprocess
call (openssl, docker, sshd, dnsmasq, nginx...) runs for real.

unittest ignores conftest.py, so the normal CI suite is unaffected.
"""
import importlib
import io
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

_REAL_RUN = subprocess.run
_REAL_SLEEP = time.sleep
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tool_module(path):
    path = os.path.abspath(path)
    if os.path.dirname(path) != _ROOT or not path.endswith(".py"):
        return None
    return os.path.basename(path)[:-3]


def _inprocess_run(args, *pargs, **kw):
    if pargs or not isinstance(args, (list, tuple)) or len(args) < 2 or args[0] != sys.executable:
        return _REAL_RUN(args, *pargs, **kw)
    name = _tool_module(args[1])
    if name is None:
        return _REAL_RUN(args, *pargs, **kw)

    text = bool(kw.get("text") or kw.get("universal_newlines") or kw.get("encoding") or kw.get("errors"))
    data = kw.get("input")
    if data is None:
        data = b""
    elif isinstance(data, str):
        data = data.encode()
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    out_b, err_b = io.BytesIO(), io.BytesIO()
    stdout = io.TextIOWrapper(out_b, encoding="utf-8", write_through=True)
    stderr = io.TextIOWrapper(err_b, encoding="utf-8", write_through=True)

    saved = (sys.argv, sys.stdin, sys.stdout, sys.stderr, dict(os.environ), os.getcwd(),
             socket.getdefaulttimeout(), time.sleep)
    rc = 0
    try:
        if kw.get("env") is not None:
            os.environ.clear()
            os.environ.update(kw["env"])
            # mutmut's own switches must survive a test that passes a minimal env
            for k in ("MUTANT_UNDER_TEST", "PY_IGNORE_IMPORTMISMATCH", "MUTMUT_DEPENDENCY_DEPTH"):
                if k in saved[4]:
                    os.environ[k] = saved[4][k]
        if kw.get("cwd"):
            os.chdir(kw["cwd"])
        # a fresh interpreter has no cached urllib opener (3.13+ binds the SSL context, and so
        # SSL_CERT_FILE, when the opener is first built)
        urllib.request.install_opener(None)
        # retry back-off sleeps (e.g. crt.sh's 2/4/6 s) only make mutants slow; nothing asserts on them
        # (only on the test's own thread: fixture servers running in other threads, e.g. a deliberately
        # slow endpoint for a --timeout test, must keep their real delays)
        time.sleep = lambda secs: _REAL_SLEEP(min(secs, 0.01) if threading.current_thread() is threading.main_thread() else secs)
        sys.argv = [args[1]] + [str(a) for a in args[2:]]
        sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr
        mod = sys.modules.get(name)
        mod = importlib.reload(mod) if mod is not None else importlib.import_module(name)
        try:
            code = mod.main()
            raise SystemExit(code)
        except SystemExit as e:
            c = e.code
            if c is None:
                rc = 0
            elif isinstance(c, int):
                rc = c & 0xFF
            else:
                print(c, file=sys.stderr)
                rc = 1
        except KeyboardInterrupt:
            rc = 130
        except BaseException:  # noqa: B902 - an uncaught exception is exit 1 with a traceback, like python
            traceback.print_exc()
            rc = 1
    finally:
        try:
            stdout.flush()
            stderr.flush()
        except ValueError:
            pass
        sys.argv, sys.stdin, sys.stdout, sys.stderr = saved[0], saved[1], saved[2], saved[3]
        os.environ.clear()
        os.environ.update(saved[4])
        os.chdir(saved[5])
        socket.setdefaulttimeout(saved[6])
        time.sleep = saved[7]

    out, err = out_b.getvalue(), err_b.getvalue()
    capture = kw.get("capture_output")
    if not capture and kw.get("stdout") is None:
        sys.stdout.write(out.decode("utf-8", "replace"))
        out = None
    if not capture and kw.get("stderr") is None:
        sys.stderr.write(err.decode("utf-8", "replace"))
        err = None
    if kw.get("stderr") == subprocess.STDOUT and out is not None:
        out, err = out + (err or b""), None
    if text:
        out = out.decode("utf-8", "replace").replace("\r\n", "\n") if out is not None else None
        err = err.decode("utf-8", "replace").replace("\r\n", "\n") if err is not None else None
    cp = subprocess.CompletedProcess(list(args), rc, out, err)
    if kw.get("check") and rc:
        raise subprocess.CalledProcessError(rc, list(args), out, err)
    return cp


if os.environ.get("MUTANT_UNDER_TEST"):
    subprocess.run = _inprocess_run
