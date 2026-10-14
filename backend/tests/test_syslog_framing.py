"""
Syslog stream framing (task 6.2) — RFC 5425 / RFC 6587.

    cd backend && source .venv/bin/activate
    pytest tests/test_syslog_framing.py -v

Framing is where a TCP syslog receiver goes wrong quietly: a decoder that
mis-splits a stream writes fragments into network_logs that look like real
records. These tests pin the behaviour that stops that happening — in
particular the cases that only appear over a real network, where a message
arrives split across several TCP reads.

RFC 5425 s4.3.1 mandates octet-counting for Syslog-over-TLS; RFC 6587 s3.4.2
describes the LF-delimited framing that rsyslog sends over plain TCP by
default. The decoder accepts both, so both are tested.
"""
from __future__ import annotations

import pytest

from app.services.ingestion.framing import FrameDecoder, FrameError, Framing

# A realistic iptables-over-syslog line, the format the Phase 5 Kali sandbox
# emitted and that parsers/iptables.py consumes.
MSG = (b"<134>Aug 24 13:32:51 kernel: [12345.678] IN=eth0 OUT= "
       b"SRC=192.168.64.2 DST=192.168.64.1 LEN=60 PROTO=TCP SPT=4444 DPT=80 SYN")


def octet_counted(*messages: bytes) -> bytes:
    """Encode messages per RFC 6587 s3.4.1: "MSG-LEN SP SYSLOG-MSG"."""
    return b"".join(str(len(m)).encode() + b" " + m for m in messages)


# --- octet-counted framing (RFC 5425, the TLS transport) -------------------

def test_single_octet_counted_message():
    decoder = FrameDecoder()
    assert decoder.feed(octet_counted(MSG)) == [MSG]
    assert decoder.framing is Framing.OCTET_COUNTED


def test_several_messages_in_one_read():
    """A busy sender coalesces messages into a single TCP segment."""
    decoder = FrameDecoder()
    assert decoder.feed(octet_counted(MSG, MSG, MSG)) == [MSG, MSG, MSG]


def test_message_split_across_reads():
    """The case that only shows up over a real network.

    TCP may deliver a message in any number of pieces. Feeding one byte at a
    time is the pathological version of that, and must still yield exactly one
    message at the end and nothing before it.
    """
    decoder = FrameDecoder()
    payload = octet_counted(MSG)
    out: list[bytes] = []
    for i in range(len(payload)):
        out.extend(decoder.feed(payload[i:i + 1]))
    assert out == [MSG]


def test_length_prefix_split_across_reads():
    """The boundary can fall inside the length prefix itself."""
    decoder = FrameDecoder()
    payload = octet_counted(MSG)
    assert decoder.feed(payload[:1]) == []       # part of the digits only
    assert decoder.feed(payload[1:]) == [MSG]


def test_partial_trailing_message_is_held_not_emitted():
    """A half-arrived message must never be emitted as though complete."""
    decoder = FrameDecoder()
    payload = octet_counted(MSG, MSG)
    cut = len(payload) - 20
    assert decoder.feed(payload[:cut]) == [MSG]  # first only
    assert decoder.pending_bytes > 0
    assert decoder.feed(payload[cut:]) == [MSG]  # second completes


def test_message_containing_a_newline_is_not_split():
    """The reason RFC 5425 mandates octet-counting.

    LF-delimited framing would break this message in two; octet-counting
    cannot, because the length is known before the body is read.
    """
    embedded = b"<134>Aug 24 13:32:51 kernel: line one\nline two"
    decoder = FrameDecoder()
    assert decoder.feed(octet_counted(embedded)) == [embedded]


# --- non-transparent framing (RFC 6587 s3.4.2, plain TCP) ------------------

def test_lf_delimited_messages():
    decoder = FrameDecoder()
    assert decoder.feed(MSG + b"\n" + MSG + b"\n") == [MSG, MSG]
    assert decoder.framing is Framing.NON_TRANSPARENT


def test_crlf_sender_is_tolerated():
    decoder = FrameDecoder()
    assert decoder.feed(MSG + b"\r\n") == [MSG]


def test_lf_message_split_across_reads():
    decoder = FrameDecoder()
    assert decoder.feed(MSG[:20]) == []
    assert decoder.feed(MSG[20:] + b"\n") == [MSG]


def test_empty_frames_are_skipped():
    """Bare newlines are keepalives, not zero-length records."""
    decoder = FrameDecoder()
    assert decoder.feed(b"\n\n" + MSG + b"\n") == [MSG]


# --- framing is detected once and then held --------------------------------

def test_framing_is_locked_after_the_first_message():
    """A sender does not switch framing mid-stream.

    Locking it in means a corrupt length prefix is reported as an error
    rather than silently reinterpreted as LF-delimited text.
    """
    decoder = FrameDecoder()
    decoder.feed(octet_counted(MSG))
    assert decoder.framing is Framing.OCTET_COUNTED
    with pytest.raises(FrameError):
        decoder.feed(b"not a length prefix and no delimiter either, at all")


# --- malformed input closes the connection rather than corrupting data -----

def test_oversized_declared_length_is_rejected():
    decoder = FrameDecoder(max_frame_bytes=1024)
    with pytest.raises(FrameError, match="exceeds max_frame_bytes"):
        decoder.feed(b"999999 " + MSG)


def test_lf_stream_with_no_trailer_is_bounded():
    """A peer that never sends a delimiter must not grow the buffer forever."""
    decoder = FrameDecoder(max_frame_bytes=256)
    with pytest.raises(FrameError):
        decoder.feed(b"<134>" + b"x" * 600)


def test_unframed_flood_is_bounded():
    decoder = FrameDecoder(max_frame_bytes=128)
    with pytest.raises(FrameError):
        decoder.feed(b"<134>" + b"x" * 1000)


def test_non_numeric_length_prefix_is_rejected():
    decoder = FrameDecoder()
    decoder.framing = Framing.OCTET_COUNTED      # as if set by an earlier message
    with pytest.raises(FrameError, match="invalid octet count"):
        decoder.feed(b"12x4 " + MSG)


# --- state hygiene ----------------------------------------------------------

def test_decoder_is_empty_after_clean_messages():
    """Nothing left buffered means no truncation warning on a clean close."""
    decoder = FrameDecoder()
    decoder.feed(octet_counted(MSG, MSG))
    assert decoder.pending_bytes == 0


def test_pending_bytes_reports_a_truncated_tail():
    decoder = FrameDecoder()
    decoder.feed(octet_counted(MSG)[:-5])
    assert decoder.pending_bytes > 0
