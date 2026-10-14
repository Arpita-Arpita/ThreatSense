"""
Syslog stream framing (task 6.2) — RFC 5425 / RFC 6587.

WHY THIS EXISTS
---------------
UDP gives message boundaries for free: one datagram is one syslog message.
TCP does not. It is a byte stream, so a receiver must be told where each
message ends, and two incompatible conventions are in use:

  OCTET-COUNTING (RFC 6587 s3.4.1, MANDATORY for TLS per RFC 5425 s4.3.1)
      "MSG-LEN SP SYSLOG-MSG", where MSG-LEN is the octet count of the
      message as ASCII digits:
          75 <134>Aug 24 13:32:51 kernel: IN=eth0 SRC=... DST=...
      Unambiguous: the length is known before the body is read, so a message
      containing a newline cannot be split.

  NON-TRANSPARENT-FRAMING (RFC 6587 s3.4.2)
      Messages separated by a trailer, in practice LF (0x0A):
          <134>Aug 24 13:32:51 kernel: IN=eth0 SRC=... DST=...\\n
      Simpler, and what rsyslog's omfwd sends over plain TCP by default, but
      it cannot represent a message containing the trailer octet.

RFC 5425 mandates octet-counting for Syslog-over-TLS, which is what NFR-04
requires. But rsyslog only emits it when explicitly configured with
TCP_Framing="octet-counted", and a misconfigured sender that falls back to
LF-delimited would otherwise be silently unparseable. The decoder therefore
accepts BOTH and reports which it saw, so the listener can log the mismatch
rather than dropping traffic in silence.

Ingestion already has one silent-loss path (unresolvable sender IPs are
counted and discarded with no log line, which cost two full NFR-01 runs
during 6.1 testing). This module deliberately does not add a second.
"""
from __future__ import annotations

from enum import Enum


class Framing(str, Enum):
    """Which RFC 6587 framing a peer is using."""

    OCTET_COUNTED = "octet-counted"        # RFC 6587 s3.4.1 / RFC 5425 s4.3.1
    NON_TRANSPARENT = "non-transparent"    # RFC 6587 s3.4.2 (LF-delimited)
    UNKNOWN = "unknown"                    # nothing decoded yet


class FrameError(Exception):
    """Unrecoverable framing violation. The connection must be closed.

    A stream whose framing is corrupt cannot be resynchronised: the receiver
    has no way to find the next message boundary, and guessing risks writing
    fragments into network_logs as if they were whole records.
    """


class FrameDecoder:
    """Incremental decoder for a single TCP/TLS connection.

    Feed it whatever bytes arrive; it returns complete syslog messages and
    retains any partial remainder for the next call. One decoder per
    connection — the buffer is per-peer state.

        decoder = FrameDecoder(max_frame_bytes=65536)
        for message in decoder.feed(chunk):
            ...

    Framing is detected from the first byte of the first message and then
    held for the life of the connection. A sender does not switch mid-stream,
    and locking it in means a corrupt length prefix is reported as an error
    rather than silently reinterpreted as LF-delimited text.
    """

    def __init__(self, max_frame_bytes: int = 64 * 1024) -> None:
        self.max_frame_bytes = max_frame_bytes
        self.framing = Framing.UNKNOWN
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        """Add received bytes; return whichever complete messages are now available."""
        self._buf.extend(chunk)

        # Guard against a peer that never sends a delimiter: without this an
        # attacker (or a broken sender) could grow this buffer without bound.
        # The check uses a generous multiple because a legitimate octet-counted
        # frame may legitimately be max_frame_bytes long and still incomplete.
        if len(self._buf) > self.max_frame_bytes * 2:
            raise FrameError(
                f"unframed data exceeded {self.max_frame_bytes * 2} bytes — "
                "peer is not delimiting messages"
            )

        messages: list[bytes] = []
        while True:
            message = self._take_one()
            if message is None:
                break
            if message:                     # skip empty frames (bare LF, keepalives)
                messages.append(message)
        return messages

    def _take_one(self) -> bytes | None:
        """Pull one message off the front of the buffer, or None if incomplete."""
        if not self._buf:
            return None

        if self.framing is Framing.UNKNOWN:
            # RFC 6587: an octet-counted frame begins with a decimal digit; a
            # non-transparent one begins with the message itself, which for
            # syslog starts with '<' (the PRI). Anything else is malformed.
            first = self._buf[0:1]
            if first.isdigit():
                self.framing = Framing.OCTET_COUNTED
            else:
                self.framing = Framing.NON_TRANSPARENT

        if self.framing is Framing.OCTET_COUNTED:
            return self._take_octet_counted()
        return self._take_non_transparent()

    def _take_octet_counted(self) -> bytes | None:
        """RFC 6587 s3.4.1 — "MSG-LEN SP SYSLOG-MSG"."""
        space = self._buf.find(b" ")
        if space == -1:
            # No length delimiter yet. A length prefix is at most a handful of
            # digits, so a long run without one means the stream is not
            # octet-counted after all and cannot be recovered.
            if len(self._buf) > 12:
                raise FrameError(
                    "octet-counted framing declared but no length delimiter found"
                )
            return None

        raw_len = bytes(self._buf[:space])
        if not raw_len.isdigit():
            raise FrameError(f"invalid octet count {raw_len!r}")

        length = int(raw_len)
        if length > self.max_frame_bytes:
            raise FrameError(
                f"frame length {length} exceeds max_frame_bytes {self.max_frame_bytes}"
            )

        start = space + 1
        end = start + length
        if len(self._buf) < end:
            return None                      # body not fully arrived yet

        message = bytes(self._buf[start:end])
        del self._buf[:end]
        return message

    def _take_non_transparent(self) -> bytes | None:
        """RFC 6587 s3.4.2 — messages separated by LF."""
        newline = self._buf.find(b"\n")
        if newline == -1:
            if len(self._buf) > self.max_frame_bytes:
                raise FrameError(
                    f"message exceeded max_frame_bytes {self.max_frame_bytes} "
                    "with no trailer"
                )
            return None

        message = bytes(self._buf[:newline])
        del self._buf[: newline + 1]
        return message.rstrip(b"\r")         # tolerate CRLF senders

    @property
    def pending_bytes(self) -> int:
        """Bytes held for the next call — useful for diagnostics."""
        return len(self._buf)
