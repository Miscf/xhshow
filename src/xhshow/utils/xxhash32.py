"""Pure-Python xxhash32 (LE input) used by the x-rap-param algorithm.

Implements XXH32 from the reference xxHash spec
(https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) so the project
does not need a C-extension dependency. ``digest()`` returns big-endian bytes
to match the layout the JS encoder writes to the wire.
"""

from __future__ import annotations

__all__ = ["xxh32_digest", "xxh32_intdigest"]

_PRIME32_1 = 0x9E3779B1
_PRIME32_2 = 0x85EBCA77
_PRIME32_3 = 0xC2B2AE3D
_PRIME32_4 = 0x27D4EB2F
_PRIME32_5 = 0x165667B1
_MASK = 0xFFFFFFFF


def _u32(x: int) -> int:
    return x & _MASK


def _rotl32(x: int, n: int) -> int:
    return _u32((x << n) | (x >> (32 - n)))


def _round(acc: int, lane: int) -> int:
    acc = _u32(acc + _u32(lane * _PRIME32_2))
    acc = _rotl32(acc, 13)
    return _u32(acc * _PRIME32_1)


def xxh32_intdigest(data: bytes, seed: int = 0) -> int:
    length = len(data)
    if length >= 16:
        v1 = _u32(seed + _PRIME32_1 + _PRIME32_2)
        v2 = _u32(seed + _PRIME32_2)
        v3 = _u32(seed + 0)
        v4 = _u32(seed - _PRIME32_1)
        i = 0
        end = length - (length % 16)
        while i < end:
            v1 = _round(v1, int.from_bytes(data[i : i + 4], "little"))
            v2 = _round(v2, int.from_bytes(data[i + 4 : i + 8], "little"))
            v3 = _round(v3, int.from_bytes(data[i + 8 : i + 12], "little"))
            v4 = _round(v4, int.from_bytes(data[i + 12 : i + 16], "little"))
            i += 16
        h = _u32(_rotl32(v1, 1) + _rotl32(v2, 7) + _rotl32(v3, 12) + _rotl32(v4, 18))
    else:
        h = _u32(seed + _PRIME32_5)
        i = 0

    h = _u32(h + length)

    while i + 4 <= length:
        h = _u32(h + _u32(int.from_bytes(data[i : i + 4], "little") * _PRIME32_3))
        h = _u32(_rotl32(h, 17) * _PRIME32_4)
        i += 4

    while i < length:
        h = _u32(h + _u32(data[i] * _PRIME32_5))
        h = _u32(_rotl32(h, 11) * _PRIME32_1)
        i += 1

    h ^= h >> 15
    h = _u32(h * _PRIME32_2)
    h ^= h >> 13
    h = _u32(h * _PRIME32_3)
    h ^= h >> 16
    return h


def xxh32_digest(data: bytes | str, seed: int = 0) -> bytes:
    """Return the xxhash32 digest as 4 big-endian bytes (matches xxhash.xxh32().digest())."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return xxh32_intdigest(data, seed).to_bytes(4, "big")
