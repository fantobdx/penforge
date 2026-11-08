"""Shim de compatibilité : re-exporte depuis penforge.ioc.extract"""
from penforge.ioc.extract import (  # noqa: F401
    extract_iocs, write_report, _text_report, _yara_rules,
    EMAIL_RE, IPV4_RE, HASH_RES, YARA_HASH_FUNCS,
    MAX_REPORT_BYTES, REPORT_NAME, YARA_NAME,
)
