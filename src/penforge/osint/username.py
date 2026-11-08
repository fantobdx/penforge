import os
import re
import subprocess

_TIMEOUT = 120
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


def _run(argv, report_path, timeout=_TIMEOUT):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    output = _strip_ansi(result.stdout)
    if result.stderr.strip():
        output += "\n--- stderr ---\n" + _strip_ansi(result.stderr)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(output)
    return output


def run_username(username, outdir):
    report = os.path.join(outdir, "sherlock-report.txt")
    return _run(["sherlock", username, "--timeout", "15"], report)
