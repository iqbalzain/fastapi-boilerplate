"""depguard — dependency governance for this repository (stdlib only).

Vets packages against ``depguard.toml`` before they are installed, audits the
lockfile for vulnerabilities and policy drift, and reports outdated pins.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
