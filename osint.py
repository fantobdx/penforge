"""Shim de compatibilité : re-exporte depuis penforge.osint.*"""
from penforge.osint import OSINT_ROOT  # noqa: F401
from penforge.osint.username import run_username  # noqa: F401
from penforge.osint.phone import run_phone  # noqa: F401
from penforge.osint.email_lookup import run_email  # noqa: F401
from penforge.osint.image import run_image  # noqa: F401
