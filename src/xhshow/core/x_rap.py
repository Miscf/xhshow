"""x-rap-param signature generator (Xiaohongshu PC Web, sdk_version 10201).

The header value is a base64-encoded blob with the following layout::

    outer (36 byte fixed header + variable body)
      [0:4]    mark = [7, 36, 1, salt_len]      # salt_len ∈ {4, 5, 6}
      [4:8]    proto_version BE u32 = 1
      [8:12]   key_len BE u32 = 20              # 16-byte AES-encrypted IV + 4 byte declarator
      [12:16]  cipher_len BE u32                # length of the cipher region
      [16:20]  xxhash32(body) BE                # body = bytes after offset 36
      [20:24]  sdk_version BE u32 = 10201
      [24:28]  cost_ms BE u32                   # outer "elapsed" time
      [28:36]  reserved (8 zero bytes)
      [36 : 36+salt_len]                        # random alphanumeric salt
      [.. : .. + 16]                            # AES-encrypted CBC IV
      [.. : .. + 4]                             # IV-length declarator [0,0,0,16]
      [.. : .. + cipher_len-4]                  # cipher (AES-encrypted blocks)
      [.. : .. + 4]                             # plaintext length BE u32

    inner plaintext (gzip-compressed before encryption)
      [0:10]   field 1000 Timestamp:  [3, 232, 0, 0] + 6 byte ts BE
      [10:16]  field 1001 XorKeyVerify: [3, 233] + xxhash32(xor_key_char) BE
      ----- everything below XOR-ed with xor_key (single ASCII char) -----
      field 1002 Uuid          [3, 234] + 4-byte length BE + 16-byte alphanum string
      field 1003 RequestHash   [3, 235] + xxhash32(full_url + body) BE
      fields 1051..1065        [4, X, 0]    automation detector flags
      field 1070               [4, 46, 0]   BrowserUseV1 (placed after 1065 in this SDK)
      fields 1066..1069        [4, X, 0]    automation detector flags
      field 1100 FieldAbnormal [4, 76, 0,0,0,0]
      fields 1071..1073        [4, X, 0]    stealth-related flags
      fields 1078,1082,1084,1088,1090   [4, X, 0,0,0,0]   *Data placeholders
      field 1092               [4, 68, 0,0,7,128]   = 1920 (window.innerWidth)
      field 1094               [4, 70, 0,0,4, 56]   = 1080 (window.innerHeight)
      field 1095               [4, 71, 0,0, 6-byte BE ts]  page-load timestamp
      field 1093               [4, 69, 0,0,0,0]
      field 1091 SignCostTime  [4, 67, 0,0,0,4, 0,cost_ms_BE_u16, 0xFF, 0xFF]
      fields 1151..1156        [4, X, 0]    HpClick event flags

The wrapping protocol ("AES-CBC-on-top-of-ECB"):

    iv_enc = AES_ECB.encrypt(iv)
    plain  = gzip_pako(payload_array)
    plain  = pad to 16-byte multiple with zero bytes
    for each 16-byte block of plain:
        block = block XOR iv
        cipher_block = AES_ECB.encrypt(block)
    cipher = concat(cipher_blocks) + BE_u32(plain_len_before_padding)
"""

from __future__ import annotations

import json
import random
import string
import time
from typing import Any, Literal

from ..utils.gzip_compat import gzip_pako
from ..utils.xxhash32 import xxh32_digest
from .aes_custom import AESCustomSBox

__all__ = ["RapParamSigner", "RapParamConfig"]


# Random salt / iv / uuid charset — observed lowercase alphanumeric.
_RAP_RANDOM_CHARSET: str = string.digits + string.ascii_lowercase


def _be(value: int, length: int = 4) -> bytes:
    return value.to_bytes(length, "big", signed=False)


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


class RapParamConfig:
    """Tunable constants for the x-rap-param algorithm.

    Only ``with_overrides`` is provided so callers can adjust constants without
    importing internal modules; everything else is intentionally read-only.
    """

    __slots__ = (
        "MARK_PREFIX",
        "PROTO_VERSION",
        "KEY_LEN",
        "SDK_VERSION",
        "RESERVED_PADDING",
        "IV_LEN_DECL",
        "SALT_LEN_MIN",
        "SALT_LEN_MAX",
        "IV_LEN",
        "PAYLOAD_HEADER",
        "XOR_MARKER",
        "DEFAULT_INNER_WIDTH",
        "DEFAULT_INNER_HEIGHT",
        "COST_MS_MIN",
        "COST_MS_MAX",
        "OUTER_COST_MS_MIN",
        "OUTER_COST_MS_MAX",
        "PAGE_LOAD_OFFSET_MS_MIN",
        "PAGE_LOAD_OFFSET_MS_MAX",
        "DEFAULT_HOST",
    )

    def __init__(self, **overrides: Any) -> None:
        self.MARK_PREFIX: tuple[int, int, int] = (7, 36, 1)
        self.PROTO_VERSION: int = 1
        self.KEY_LEN: int = 20
        self.SDK_VERSION: int = 10201
        self.RESERVED_PADDING: bytes = b"\x00" * 8
        self.IV_LEN_DECL: bytes = b"\x00\x00\x00\x10"
        self.SALT_LEN_MIN: int = 4
        self.SALT_LEN_MAX: int = 6
        self.IV_LEN: int = 16
        self.PAYLOAD_HEADER: bytes = bytes([3, 232, 0, 0])
        self.XOR_MARKER: bytes = bytes([3, 233])
        self.DEFAULT_INNER_WIDTH: int = 1920
        self.DEFAULT_INNER_HEIGHT: int = 1080
        self.COST_MS_MIN: int = 8
        self.COST_MS_MAX: int = 14
        self.OUTER_COST_MS_MIN: int = 8
        self.OUTER_COST_MS_MAX: int = 14
        self.PAGE_LOAD_OFFSET_MS_MIN: int = 10
        self.PAGE_LOAD_OFFSET_MS_MAX: int = 30_000
        self.DEFAULT_HOST: str = "edith.xiaohongshu.com"
        for k, v in overrides.items():
            if k not in self.__slots__:
                raise AttributeError(f"unknown RapParamConfig field: {k}")
            setattr(self, k, v)

    def with_overrides(self, **kwargs: Any) -> RapParamConfig:
        merged = {slot: getattr(self, slot) for slot in self.__slots__}
        merged.update(kwargs)
        return RapParamConfig(**merged)


class RapParamSigner:
    """Generate the ``x-rap-param`` request header.

    Instantiate once and call :meth:`sign` per request. The signer keeps a
    stable ``page_load_timestamp_ms`` for the lifetime of the instance — the
    JSVMP sets it once at module-init and reuses it across calls.
    """

    def __init__(
        self,
        config: RapParamConfig | None = None,
        *,
        page_load_timestamp_ms: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.config = config or RapParamConfig()
        self._rng = rng or random.Random()
        self._aes = AESCustomSBox()
        if page_load_timestamp_ms is None:
            now_ms = int(time.time() * 1000)
            offset = self._rng.randint(
                self.config.PAGE_LOAD_OFFSET_MS_MIN,
                self.config.PAGE_LOAD_OFFSET_MS_MAX,
            )
            page_load_timestamp_ms = now_ms - offset
        self.page_load_timestamp_ms: int = page_load_timestamp_ms

    # ------------------------------------------------------------------ helpers

    def _random_string(self, n: int) -> str:
        return "".join(self._rng.choice(_RAP_RANDOM_CHARSET) for _ in range(n))

    @staticmethod
    def build_request_info(
        method: str,
        uri: str,
        payload: dict[str, Any] | str | None,
        host: str,
    ) -> str:
        """Compose the string fed to xxhash32 for the RequestHash field.

        Format: ``//{host}{uri}{body}`` — scheme-relative URL, mirroring how the
        XHS frontend opens XHR requests in the real browser. For POST, ``body``
        is ``JSON.stringify(payload)``; for GET it is the empty string.
        """
        url = f"//{host}{uri}"
        if method.upper() == "POST":
            if isinstance(payload, str):
                body_str = payload
            else:
                body_str = json.dumps(payload or {}, separators=(",", ":"), ensure_ascii=False)
            return url + body_str
        return url

    # --------------------------------------------------------------- inner data

    def _build_payload(
        self,
        timestamp_ms: int,
        request_info: str,
        cost_ms: int,
        page_load_ts_ms: int,
    ) -> bytes:
        cfg = self.config
        out = bytearray()

        # field 1000 Timestamp: [3,232,0,0] + 6-byte BE timestamp
        out += cfg.PAYLOAD_HEADER
        out += _be(timestamp_ms, 6)

        # field 1001 XorKeyVerify: [3,233] + xxhash32(xor_key_char)
        xor_key_char = self._rng.choice(_RAP_RANDOM_CHARSET)
        xk = ord(xor_key_char)
        out += cfg.XOR_MARKER
        out += xxh32_digest(xor_key_char)

        # the body below is XOR-encoded with xk
        body = bytearray()

        # field 1002 Uuid
        uuid_str = self._random_string(16).encode("ascii")
        body += _be(1002, 2) + _be(len(uuid_str), 4) + uuid_str

        # field 1003 RequestHash
        body += _be(1003, 2) + xxh32_digest(request_info)

        # 1-byte flag fields, in the exact order observed in the SDK 10201 stream:
        # 1051..1065, 1070 (jumped early), 1066..1069
        flag_order = [*range(1051, 1066), 1070, 1066, 1067, 1068, 1069]
        for fid in flag_order:
            body += _be(fid, 2) + b"\x00"

        # field 1100 FieldAbnormal: 4-byte zero
        body += _be(1100, 2) + b"\x00\x00\x00\x00"

        # stealth flags 1071..1073
        for fid in (1071, 1072, 1073):
            body += _be(fid, 2) + b"\x00"

        # *Data placeholders 1078, 1082, 1084, 1088, 1090: 4-byte zero each
        for fid in (1078, 1082, 1084, 1088, 1090):
            body += _be(fid, 2) + b"\x00\x00\x00\x00"

        # field 1092: window.innerWidth (4-byte BE)
        body += _be(1092, 2) + _be(cfg.DEFAULT_INNER_WIDTH, 4)
        # field 1094: window.innerHeight (4-byte BE)
        body += _be(1094, 2) + _be(cfg.DEFAULT_INNER_HEIGHT, 4)
        # field 1095: page-load timestamp (2-byte padding + 6-byte BE ts)
        body += _be(1095, 2) + b"\x00\x00" + _be(page_load_ts_ms, 6)
        # field 1093: zero
        body += _be(1093, 2) + b"\x00\x00\x00\x00"

        # field 1091 SignCostTime: 4-byte constant 4 + 4-byte (cost_u16 << 16 | 0xFFFF)
        cost_block = _be(4, 4) + _be(cost_ms, 2) + b"\xff\xff"
        body += _be(1091, 2) + cost_block

        # HP click events 1151..1156
        for fid in range(1151, 1157):
            body += _be(fid, 2) + b"\x00"

        out += _xor_bytes(body, xk)
        return bytes(out)

    # ---------------------------------------------------------------- envelope

    def _wrap_envelope(
        self,
        payload_bytes: bytes,
        outer_cost_ms: int,
    ) -> bytes:
        cfg = self.config

        gz = gzip_pako(payload_bytes)
        gz_len = len(gz)

        iv = self._random_string(cfg.IV_LEN).encode("ascii")
        iv_enc = self._aes.encrypt_block(iv)

        # zero-pad gz to a multiple of 16 bytes
        pad_len = (-gz_len) % 16
        gz_padded = gz + b"\x00" * pad_len

        # XOR-with-IV then ECB-encrypt each 16-byte block
        cipher = bytearray()
        for i in range(0, len(gz_padded), 16):
            block = bytes(b ^ k for b, k in zip(gz_padded[i : i + 16], iv, strict=False))
            cipher += self._aes.encrypt_block(block)
        # 4 trailing bytes = original (pre-padding) gzip length
        cipher += _be(gz_len, 4)

        salt_len = self._rng.randint(cfg.SALT_LEN_MIN, cfg.SALT_LEN_MAX)
        salt = self._random_string(salt_len).encode("ascii")

        body = bytearray()
        body += salt
        body += iv_enc
        body += cfg.IV_LEN_DECL
        body += cipher

        body_xxhash = xxh32_digest(bytes(body))

        header = bytearray()
        header += bytes(cfg.MARK_PREFIX) + bytes([salt_len])
        header += _be(cfg.PROTO_VERSION)
        header += _be(cfg.KEY_LEN)
        header += _be(len(cipher))
        header += body_xxhash
        header += _be(cfg.SDK_VERSION)
        header += _be(outer_cost_ms)
        header += cfg.RESERVED_PADDING

        return bytes(header) + bytes(body)

    # -------------------------------------------------------------- public API

    def sign(
        self,
        method: Literal["GET", "POST"] | str,
        uri: str,
        payload: dict[str, Any] | str | None = None,
        *,
        host: str | None = None,
        timestamp: float | None = None,
        page_load_timestamp_ms: int | None = None,
    ) -> str:
        """Compute the x-rap-param header value as a base64 string.

        Args:
            method: HTTP method ("GET" or "POST").
            uri: Path (or path?query for GET).
            payload: POST body (dict or already-stringified JSON). Ignored for GET.
            host: Override the host used in the RequestHash hash input. Defaults
                to ``edith.xiaohongshu.com``.
            timestamp: Override the inner timestamp (seconds since epoch).
            page_load_timestamp_ms: Override the page-load timestamp (ms). Falls
                back to the value captured at signer-init time.
        """
        import base64

        cfg = self.config
        if timestamp is None:
            timestamp = time.time()
        ts_ms = int(timestamp * 1000)

        page_load_ts = page_load_timestamp_ms if page_load_timestamp_ms is not None else self.page_load_timestamp_ms

        request_info = self.build_request_info(method, uri, payload, host or cfg.DEFAULT_HOST)

        cost_ms = self._rng.randint(cfg.COST_MS_MIN, cfg.COST_MS_MAX)
        outer_cost_ms = self._rng.randint(cfg.OUTER_COST_MS_MIN, cfg.OUTER_COST_MS_MAX)

        plain = self._build_payload(ts_ms, request_info, cost_ms, page_load_ts)
        envelope = self._wrap_envelope(plain, outer_cost_ms)
        return base64.b64encode(envelope).decode("ascii")
