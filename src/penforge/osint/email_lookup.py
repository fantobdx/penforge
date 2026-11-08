import os
import re
import subprocess

_TIMEOUT = 120
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

_HOLEHE_SKIP = re.compile(
    r"^(Twitter\s*:|Github\s*:|For BTC|\*+|"
    r"\[.\] Email used|^\s*$)",
    re.IGNORECASE,
)


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


def run_email(email, outdir):
    report = os.path.join(outdir, "holehe-report.txt")
    result = subprocess.run(
        ["holehe", email, "--only-used", "--no-clear"],
        capture_output=True, text=True, timeout=_TIMEOUT,
    )
    lines = []
    for raw_line in _strip_ansi(result.stdout).splitlines():
        line = raw_line.strip()
        if not line or _HOLEHE_SKIP.match(line):
            continue
        lines.append(line)
    output = "\n".join(lines) if lines else "(aucun service trouvé pour cet email)"
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(output)
    return output
