"""Collection modules.

Submodules are imported by the engine on demand; this package stays import-free
so that ``context`` and the modules can reference each other without cycles.
"""

__all__ = [
    "breaches",
    "dorks",
    "dns_intel",
    "github",
    "gravatar",
    "handle_probe",
    "identity",
    "reputation",
    "smtp_verify",
    "urlscan",
]
