import os

import requests


def run_domain(domain: str, outdir: str) -> str:
    report_path = os.path.join(outdir, "domain-osint-report.txt")
    sep = "=" * 52
    lines = []

    # crt.sh
    lines += [sep, "CERTIFICATS (crt.sh)", sep]
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        subdomains = sorted({
            entry["name_value"].lower()
            for entry in data
            if "name_value" in entry and "*" not in entry["name_value"]
        })
        lines.append(f"{len(subdomains)} sous-domaine(s) dans les certificats :")
        for sub in subdomains[:100]:
            lines.append(f"  {sub}")
        if len(subdomains) > 100:
            lines.append(f"  ... et {len(subdomains) - 100} autres")
    except Exception as exc:
        lines.append(f"(erreur crt.sh : {exc})")

    # Wayback CDX
    lines += ["", sep, "URLs HISTORIQUES (Wayback CDX)", sep]
    try:
        resp = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "500",
            },
            timeout=30,
        )
        resp.raise_for_status()
        urls = [u for u in resp.text.splitlines() if u.strip()]
        lines.append(f"{len(urls)} URL(s) historique(s) :")
        for u in urls[:100]:
            lines.append(f"  {u}")
        if len(urls) > 100:
            lines.append(f"  ... et {len(urls) - 100} autres")
    except Exception as exc:
        lines.append(f"(erreur Wayback CDX : {exc})")

    output = "\n".join(lines)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(output)
    return output
