"""pako-compatible gzip helpers (`gzip_pako` / `ungzip_pako`).

The browser-side x-rap-param encoder uses ``pako`` to gzip the inner payload.
Python's stdlib ``gzip`` adds an OS byte (255) and full mtime, which the server
rejects. These helpers emit the exact byte layout pako produces by default:
fixed FLG=0, mtime=current epoch, XFL=0, OS=3 (Unix).
"""

from __future__ import annotations

import time
import zlib
from collections.abc import Sequence

__all__ = ["gzip_pako", "ungzip_pako"]


def _u32_le(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _deflate_raw(data: bytes, level: int) -> bytes:
    c = zlib.compressobj(
        level=level,
        method=zlib.DEFLATED,
        wbits=-15,
        memLevel=8,
        strategy=zlib.Z_DEFAULT_STRATEGY,
    )
    return c.compress(data) + c.flush(zlib.Z_FINISH)


def gzip_pako(
    data: bytes,
    *,
    mtime: int | None = None,
    level: int = zlib.Z_DEFAULT_COMPRESSION,
    xfl: int = 0,
    os_byte: int = 3,
) -> bytes:
    """Produce gzip output matching pako defaults: ``FLG=0, OS=3``."""
    if mtime is None:
        mtime = int(time.time())
    header = bytes([0x1F, 0x8B, 0x08, 0x00]) + _u32_le(mtime) + bytes([xfl & 0xFF, os_byte & 0xFF])
    body = _deflate_raw(data, level)
    trailer = _u32_le(zlib.crc32(data) & 0xFFFFFFFF) + _u32_le(len(data) & 0xFFFFFFFF)
    return header + body + trailer


def ungzip_pako(gz: bytes | Sequence[int], *, verify: bool = True) -> bytes:
    """Decode the FLG=0 single-member gzip stream produced by ``gzip_pako``."""
    if not isinstance(gz, bytes | bytearray):
        gz = bytes(gz)
    if len(gz) < 18 or gz[0] != 0x1F or gz[1] != 0x8B:
        raise ValueError("bad gzip magic")
    if gz[2] != 0x08:
        raise ValueError("unsupported method")
    if gz[3] != 0:
        raise NotImplementedError("only FLG=0 supported")

    body = gz[10:-8]
    crc_expect = int.from_bytes(gz[-8:-4], "little")
    isize_expect = int.from_bytes(gz[-4:], "little")

    d = zlib.decompressobj(wbits=-15)
    data = d.decompress(body) + d.flush()
    if d.unused_data:
        raise ValueError("extra data after raw deflate stream")

    if verify:
        if zlib.crc32(data) & 0xFFFFFFFF != crc_expect:
            raise ValueError("crc32 mismatch")
        if len(data) & 0xFFFFFFFF != isize_expect:
            raise ValueError("isize mismatch")
    return data
