import os
import re
import subprocess
import threading

_TIMEOUT_SHERLOCK = 120
_TIMEOUT_MAIGRET = 180
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


def _run_capture(argv, timeout):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        output = _strip_ansi(result.stdout)
        if result.stderr.strip():
            output += "\n--- stderr ---\n" + _strip_ansi(result.stderr)
        return output
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return f"(timeout après {timeout}s)\n"


def run_username(username, outdir):
    report = os.path.join(outdir, "username-report.txt")

    sherlock_result = {}
    maigret_result = {}

    def _sherlock():
        sherlock_result["out"] = _run_capture(
            ["sherlock", username, "--timeout", "15", "--print-found", "--no-color"], _TIMEOUT_SHERLOCK
        )

    def _maigret():
        try:
            import maigret as _maigret  # noqa: F401
        except ImportError:
            maigret_result["out"] = ""
            return
        maigret_result["out"] = _run_capture(
            ["maigret", username, "--no-color", "--timeout", "15", "-a", "--html"],
            _TIMEOUT_MAIGRET,
        )

    t1 = threading.Thread(target=_sherlock, daemon=True)
    t2 = threading.Thread(target=_maigret, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    sep = "=" * 52
    parts = []
    sherlock_out = sherlock_result.get("out", "")
    if sherlock_out:
        parts += [sep, "Sherlock (rapide, 479 sites)", sep, sherlock_out]
    maigret_out = maigret_result.get("out", "")
    if maigret_out:
        parts += [sep, "Maigret (approfondi, 3100+ sites)", sep, maigret_out]
    output = "\n".join(parts) if parts else "(aucun résultat)"

    with open(report, "w", encoding="utf-8") as fh:
        fh.write(output)
    return output
