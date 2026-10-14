"""
Syslog over TLS on TCP 6514 (task 6.2) — NFR-04.

    cd backend && source .venv/bin/activate
    pytest tests/test_tls_listener.py -v

Proposal Section 3, Table 11, NFR-04 — Requirement (verbatim, in part):
    "All web application, API, and external-service traffic must be encrypted
    using TLS 1.2 or higher. Syslog over TLS on TCP port 6514 must be used
    where supported. Standard Syslog ports 514 and 1514 may be used only
    within the isolated testing environment."

Proposal Section 3, Table 11, NFR-04 — Measurement / Metric (verbatim, in part):
    "verification of Syslog-over-TLS configuration where enabled"

These are integration tests, not mocks: each one generates a real certificate,
starts the real listener protocol on a real socket, completes a real TLS
handshake, and asserts on rows in the real database. A mocked TLS test would
prove only that the mock was called.

Certificates are generated per-session into a temporary directory, so nothing
here depends on backend/certs/ existing and nothing is left behind.
"""
from __future__ import annotations

import asyncio
import datetime
import ssl
import uuid

import pytest
from sqlalchemy import delete, select

from app.config import settings
from app.database import SessionLocal
from app.models import DataSource, NetworkLog, SourceType, SourceStatus, TransportType
from app.models import Administrator
from app.services.ingestion.framing import Framing
from app.services.ingestion.listener import IngestionService, SyslogStreamProtocol
from app.services.ingestion.tls import TLSConfigError, build_server_context, describe

MSG = (b"<134>Aug 24 13:32:51 kernel: [12345.678] IN=eth0 OUT= "
       b"SRC=127.0.0.1 DST=192.168.1.5 LEN=60 PROTO=TCP SPT=4444 DPT=80 SYN")


def octet_counted(*messages: bytes) -> bytes:
    """RFC 6587 s3.4.1 framing, which RFC 5425 s4.3.1 mandates for TLS."""
    return b"".join(str(len(m)).encode() + b" " + m for m in messages)


# --- fixtures ---------------------------------------------------------------

@pytest.fixture(scope="module")
def cert_pair(tmp_path_factory):
    """A real self-signed certificate, generated in-process.

    Uses `cryptography`, which ships as a bcrypt/pyjwt dependency, so this
    needs no openssl binary and no fixture files in the repository.
    """
    crypto = pytest.importorskip("cryptography",
                                 reason="cryptography is needed to mint a test certificate")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    directory = tmp_path_factory.mktemp("certs")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "threatsense-test")])
    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )

    crt = directory / "test.crt"
    keyfile = directory / "test.key"
    crt.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return {"certfile": str(crt), "keyfile": str(keyfile)}


@pytest.fixture()
def loopback_source():
    """A data_sources row for 127.0.0.1.

    Without one, resolve_source returns None and every message is discarded —
    the silent-drop path that cost two NFR-01 runs during 6.1. The test would
    otherwise pass its TLS assertions while writing nothing.
    """
    with SessionLocal() as db:
        admin = db.scalar(select(Administrator))
        if admin is None:
            pytest.skip("no administrator seeded; run db/seed.py")
        existing = db.scalar(select(DataSource).where(DataSource.ip_address == "127.0.0.1"))
        if existing:
            yield existing.source_id
            return
        row = DataSource(admin_id=admin.admin_id, name=f"tls-test-{uuid.uuid4().hex[:6]}",
                         type=SourceType.SYSLOG, ip_address="127.0.0.1",
                         transport=TransportType.TLS, port=settings.syslog_tls_port,
                         status=SourceStatus.ACTIVE)
        db.add(row)
        db.commit()
        source_id = row.source_id
    yield source_id
    with SessionLocal() as db:
        db.execute(delete(NetworkLog).where(NetworkLog.source_id == source_id))
        db.execute(delete(DataSource).where(DataSource.source_id == source_id))
        db.commit()


async def _serve(service, cert_pair, **context_kwargs):
    """Start the real listener protocol on an ephemeral port."""
    context = build_server_context(
        certfile=cert_pair["certfile"], keyfile=cert_pair["keyfile"], **context_kwargs)
    server = await asyncio.get_running_loop().create_server(
        lambda: SyslogStreamProtocol(service, "TLS"),
        host="127.0.0.1", port=0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


def _client_context(cert_pair) -> ssl.SSLContext:
    """A client that trusts the test certificate — no verification bypass."""
    context = ssl.create_default_context(cafile=cert_pair["certfile"])
    context.check_hostname = False       # SAN covers 127.0.0.1; CN is not a hostname
    return context


# --- the encrypted path end to end -----------------------------------------

@pytest.mark.anyio
async def test_message_over_tls_reaches_the_database(cert_pair, loopback_source):
    """The whole NFR-04 clause in one test: TLS in, row out."""
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    async with server:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=_client_context(cert_pair))
        writer.write(octet_counted(MSG))
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        await writer.wait_closed()

    assert len(service.buffer) == 1, "message did not reach the ingestion buffer"
    await service.flush()

    with SessionLocal() as db:
        row = db.scalar(select(NetworkLog)
                        .where(NetworkLog.source_id == loopback_source)
                        .order_by(NetworkLog.ingested_at.desc()))
    assert row is not None
    # Was: `row.src_ip == "192.168.64.2" or row.src_ip is not None`, which any
    # non-null value satisfied — and the first branch was never true anyway,
    # since MSG carries SRC=127.0.0.1. It asserted nothing about parsing.
    assert str(row.src_ip) == "127.0.0.1", "SRC= was not parsed from the frame"
    assert str(row.dst_ip) == "192.168.1.5"
    assert row.protocol == "TCP"
    assert row.packet_size == 60          # LEN=, not the length of the line


@pytest.mark.anyio
async def test_handshake_negotiates_tls_1_2_or_higher(cert_pair, loopback_source):
    """Table 11, NFR-04: "encrypted using TLS 1.2 or higher"."""
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    async with server:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=_client_context(cert_pair))
        negotiated = writer.get_extra_info("ssl_object").version()
        writer.close()
        await writer.wait_closed()

    assert negotiated in ("TLSv1.2", "TLSv1.3"), f"negotiated {negotiated}"


@pytest.mark.anyio
async def test_tls_1_1_client_is_refused(cert_pair, loopback_source):
    """The floor must actually be enforced, not merely configured.

    A client pinned below the minimum must fail the handshake rather than
    being quietly accepted.
    """
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    weak = ssl.create_default_context(cafile=cert_pair["certfile"])
    weak.check_hostname = False
    try:
        weak.maximum_version = ssl.TLSVersion.TLSv1_1
    except ValueError:                                   # pragma: no cover
        pytest.skip("this OpenSSL build cannot express a TLS 1.1 ceiling")

    async with server:
        with pytest.raises((ssl.SSLError, OSError, ConnectionResetError)):
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=weak)
            writer.close()
            await writer.wait_closed()


@pytest.mark.anyio
async def test_plaintext_client_cannot_talk_to_the_tls_port(cert_pair, loopback_source):
    """Port 6514 must not accept unencrypted syslog."""
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)  # no ssl=
        writer.write(octet_counted(MSG))
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, OSError):
            pass

    assert service.buffer == [], "plaintext data was accepted on the TLS port"


@pytest.mark.anyio
async def test_several_messages_over_one_connection(cert_pair, loopback_source):
    """A real sender holds one connection open and streams."""
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    async with server:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=_client_context(cert_pair))
        writer.write(octet_counted(MSG, MSG, MSG))
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        await writer.wait_closed()

    assert len(service.buffer) == 3


@pytest.mark.anyio
async def test_lf_framed_sender_is_accepted(cert_pair, loopback_source):
    """rsyslog over TCP defaults to LF framing rather than octet-counting.

    RFC 5425 mandates octet-counting for TLS, but a misconfigured sender that
    sends LF-delimited messages should be ingested rather than silently
    dropped — ingestion already has one silent-loss path too many.
    """
    service = IngestionService(SessionLocal)
    server, port = await _serve(service, cert_pair)

    async with server:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=_client_context(cert_pair))
        writer.write(MSG + b"\n" + MSG + b"\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        await writer.wait_closed()

    assert len(service.buffer) == 2


# --- configuration failures are fatal, not silent downgrades ---------------

def test_missing_certificate_raises_rather_than_falling_back():
    """A collector that quietly serves plaintext when its cert is missing
    would void the NFR-04 evidence. Start-up must fail instead."""
    with pytest.raises(TLSConfigError, match="certificate pair is missing"):
        build_server_context(certfile="/nonexistent.crt", keyfile="/nonexistent.key")


def test_unknown_minimum_version_is_rejected(cert_pair):
    with pytest.raises(TLSConfigError, match="unsupported"):
        build_server_context(min_version="TLSv1_0", **cert_pair)


def test_mutual_auth_without_a_ca_is_rejected(cert_pair):
    """Asking for client certificates without a CA cannot verify anything."""
    with pytest.raises(TLSConfigError, match="CA bundle"):
        build_server_context(require_client_cert=True, **cert_pair)


def test_configured_defaults_match_the_requirement():
    """6514 and a TLS 1.2 floor are the numbers Table 11 states."""
    assert settings.syslog_tls_port == 6514
    assert settings.syslog_tls_min_version in ("TLSv1_2", "TLSv1_3")


def test_describe_reports_the_floor_for_the_startup_log(cert_pair):
    context = build_server_context(**cert_pair)
    summary = describe(context)
    assert "TLSv1_2" in summary and "server-only" in summary
