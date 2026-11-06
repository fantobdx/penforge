"""Extraction d'IOC (emails, IP publiques, hashes) depuis les rapports d'un scan.

Adapté de DARKWATCH-OSINT (analyzer/ioc_parser.py, licence MIT) : regex seules, sans LLM.
Produit un résumé texte et un fichier YARA contenant une règle par hash MD5, SHA1 ou SHA256.
"""

import ipaddress
import os
import re

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
HASH_RES = {
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "sha512": re.compile(r"\b[0-9a-fA-F]{128}\b"),
}
# Fonctions du module hash de YARA : SHA512 n'en fait pas partie, il reste dans le résumé texte.
YARA_HASH_FUNCS = {
    "md5": "hash.md5(0, filesize)",
    "sha1": "hash.sha1(0, filesize)",
    "sha256": "hash.sha256(0, filesize)",
}
MAX_REPORT_BYTES = 5 * 1024 * 1024
REPORT_NAME = "iocs-report.txt"
YARA_NAME = "iocs.yar"


def _is_public_ipv4(candidate):
    try:
        return ipaddress.ip_address(candidate).is_global
    except ValueError:
        return False


def extract_iocs(text):
    iocs = {
        "emails": set(EMAIL_RE.findall(text)),
        "ips": {ip for ip in IPV4_RE.findall(text) if _is_public_ipv4(ip)},
    }
    for algo, regex in HASH_RES.items():
        iocs[algo] = {h.lower() for h in regex.findall(text)}
    return iocs


def _text_report(iocs):
    sections = (
        ("Emails", iocs["emails"]),
        ("IP publiques", iocs["ips"]),
        ("MD5", iocs["md5"]),
        ("SHA1", iocs["sha1"]),
        ("SHA256", iocs["sha256"]),
        ("SHA512", iocs["sha512"]),
    )
    lines = []
    for title, values in sections:
        if values:
            lines.append(f"{title} ({len(values)}) :")
            lines.extend(f"  {value}" for value in sorted(values))
    return "\n".join(lines) + "\n" if lines else "aucun IOC détecté\n"


def _yara_rules(iocs):
    rules = []
    for algo, func in YARA_HASH_FUNCS.items():
        for value in sorted(iocs[algo]):
            rules.append(
                f"rule ioc_{algo}_{value} {{\n"
                f'    meta:\n        source = "pentest scan"\n'
                f"    condition:\n        {func} == \"{value}\"\n"
                "}\n"
            )
    return "\n".join(rules) if rules else "// aucun hash détecté\n"


def write_report(scan_dir):
    if not os.path.isdir(scan_dir):
        return
    iocs = {key: set() for key in ("emails", "ips", "md5", "sha1", "sha256", "sha512")}
    for root, _dirs, files in os.walk(scan_dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                if name in (REPORT_NAME, YARA_NAME) or os.path.getsize(path) > MAX_REPORT_BYTES:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    found = extract_iocs(fh.read())
            except OSError:
                continue
            for key in iocs:
                iocs[key] |= found[key]

    with open(os.path.join(scan_dir, REPORT_NAME), "w", encoding="utf-8") as fh:
        fh.write(_text_report(iocs))
    with open(os.path.join(scan_dir, YARA_NAME), "w", encoding="utf-8") as fh:
        fh.write(_yara_rules(iocs))
