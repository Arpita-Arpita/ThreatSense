"""
TLS context for the Syslog-over-TLS listener (task 6.2).

Proposal Section 3, Table 11, NFR-04 — Requirement (verbatim):
    "All web application, API, and external-service traffic must be encrypted
    using TLS 1.2 or higher. Syslog over TLS on TCP port 6514 must be used
    where supported. Standard Syslog ports 514 and 1514 may be used only
    within the isolated testing environment. Passwords must be hashed with
    bcrypt (cost factor >= 12). JWTs must expire after 60 minutes and be
    returned using HttpOnly, Secure, SameSite=Strict cookies."

Proposal Section 3, Table 11, NFR-04 — Measurement / Metric (verbatim):
    "SSL Labs scan (minimum A rating); verification of Syslog-over-TLS
    configuration where enabled; inspection of the bcrypt cost factor in
    source code; validation of JWT cookie attributes during integration
    testing."

This module covers the "Syslog over TLS on TCP port 6514" clause and the
"TLS 1.2 or higher" floor. It is separate from the listener so the version
and cipher policy sits in one auditable place rather than being buried in
connection-handling code.

SCOPE, STATED HONESTLY
----------------------
This is a one-way (server-authenticated) TLS listener with a self-signed
certificate for local demonstration. RFC 5425 s4.2.1 recommends mutual
authentication for production Syslog-over-TLS, where the collector also
verifies a client certificate. That is NOT implemented: the MVP has a single
trusted sender on an isolated host-only network, and issuing client
certificates would need a CA that does not exist here.

The consequence is that any host able to reach port 6514 can submit logs; the
sender-IP check in IngestionService.resolve_source is the only sender
control. Set syslog_tls_require_client_cert and provide a CA bundle to turn
mutual authentication on when a CA is available.
"""
from __future__ import annotations

import logging
import ssl
from pathlib import Path

logger = logging.getLogger("threatsense.ingest")

# NFR-04: "TLS 1.2 or higher". Mapping the configured floor to the ssl
# constant explicitly, rather than trusting the library default, means the
# floor is visible in source for the measurement column's "verification of
# Syslog-over-TLS configuration".
_MIN_VERSIONS = {
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
}


class TLSConfigError(RuntimeError):
    """Raised when TLS is enabled but cannot be configured.

    Deliberately fatal rather than falling back to plaintext. A collector that
    silently downgrades to an unencrypted port when its certificate is missing
    would satisfy nobody's threat model and would make the NFR-04 evidence a
    lie.
    """


def build_server_context(certfile: str, keyfile: str, min_version: str = "TLSv1_2",
                         ca_file: str | None = None,
                         require_client_cert: bool = False) -> ssl.SSLContext:
    """Build the server-side SSLContext for port 6514.

    Raises TLSConfigError if the certificate or key is missing or unusable,
    so a misconfigured deployment fails at start-up rather than at the first
    connection.
    """
    cert_path, key_path = Path(certfile), Path(keyfile)
    if not cert_path.exists() or not key_path.exists():
        raise TLSConfigError(
            f"TLS is enabled but the certificate pair is missing:\n"
            f"  certfile: {cert_path}\n"
            f"  keyfile : {key_path}\n"
            f"Generate a self-signed pair for local use:\n"
            f"  ./scripts/generate_dev_cert.sh"
        )

    if min_version not in _MIN_VERSIONS:
        raise TLSConfigError(
            f"unsupported syslog_tls_min_version {min_version!r}; "
            f"expected one of {sorted(_MIN_VERSIONS)}"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # NFR-04's "TLS 1.2 or higher" floor. maximum_version is left at the
    # library default so TLS 1.3 is negotiated when both ends support it.
    context.minimum_version = _MIN_VERSIONS[min_version]

    try:
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except ssl.SSLError as exc:
        raise TLSConfigError(
            f"could not load the certificate pair ({exc}). If the key is "
            f"encrypted, decrypt it — the listener runs unattended and cannot "
            f"prompt for a passphrase."
        ) from exc

    if require_client_cert:
        # RFC 5425 s4.2.1 mutual authentication. Off by default; see the module
        # docstring for why.
        if not ca_file or not Path(ca_file).exists():
            raise TLSConfigError(
                "syslog_tls_require_client_cert is set but no CA bundle was "
                "provided — client certificates cannot be verified without one."
            )
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_file)
        logger.info("TLS: mutual authentication ON (CA %s)", ca_file)
    else:
        context.verify_mode = ssl.CERT_NONE

    return context


def describe(context: ssl.SSLContext) -> str:
    """One-line summary for the start-up log — this IS the NFR-04 evidence line."""
    mutual = "mutual" if context.verify_mode == ssl.CERT_REQUIRED else "server-only"
    return f"min={context.minimum_version.name}, auth={mutual}"
