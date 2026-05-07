"""End-to-end tests for the x-rap-param signer.

Each test signs, then decodes the wire format with an in-line decoder and
asserts on structural invariants. Cross-checked against the SDK 10201 byte
layout captured from a working JSVMP run.
"""

from __future__ import annotations

import base64
import random
import time

import pytest

from xhshow import RapParamConfig, RapParamSigner, Xhshow
from xhshow.core.aes_custom import AESCustomSBox
from xhshow.utils.gzip_compat import ungzip_pako
from xhshow.utils.xxhash32 import xxh32_digest, xxh32_intdigest

# ---------------------------------------------------------------- helpers


def _decode(sig_b64: str) -> dict:
    raw = base64.b64decode(sig_b64)
    data = list(raw)

    out: dict = {
        "mark": data[0:4],
        "proto": int.from_bytes(bytes(data[4:8]), "big"),
        "key_len": int.from_bytes(bytes(data[8:12]), "big"),
        "cipher_len": int.from_bytes(bytes(data[12:16]), "big"),
        "outer_xxhash": bytes(data[16:20]),
        "sdk": int.from_bytes(bytes(data[20:24]), "big"),
        "outer_cost": int.from_bytes(bytes(data[24:28]), "big"),
        "padding": data[28:36],
    }

    salt_len = data[3]
    out["salt_len"] = salt_len
    out["salt"] = bytes(data[36 : 36 + salt_len])

    aes = AESCustomSBox()
    out["iv"] = aes.decrypt_block(bytes(data[36 + salt_len : 36 + salt_len + 16]))

    cipher_start = 36 + salt_len + 20
    cipher = bytes(data[cipher_start : cipher_start + out["cipher_len"]])
    out["plain_len"] = int.from_bytes(cipher[-4:], "big")

    decrypted = bytearray()
    for i in range(0, len(cipher) - 4, 16):
        decrypted.extend(aes.decrypt_block(cipher[i : i + 16]))
    gz = bytes(b ^ k for b, k in zip(decrypted, out["iv"] * (len(decrypted) // 16), strict=False))
    out["payload"] = ungzip_pako(gz[: out["plain_len"]])

    pl = out["payload"]
    out["inner_ts_ms"] = int.from_bytes(pl[4:10], "big")
    xor_target = pl[12:16]
    xk = next(ord(ch) for ch in "0123456789abcdefghijklmnopqrstuvwxyz" if xxh32_digest(ch) == xor_target)
    out["xor_key"] = chr(xk)
    out["decoded_payload"] = bytes(list(pl[:16]) + [b ^ xk for b in pl[16:]])
    return out


def _walk_fields(decoded: bytes) -> list[tuple[int, bytes]]:
    """Walk an XOR-decoded payload starting at offset 16, return (fid, raw_value_bytes)."""
    field_widths = {
        1002: ("tlv", None),  # 4-byte length + N
        1003: ("fixed", 4),
        1100: ("fixed", 4),
        1078: ("fixed", 4),
        1082: ("fixed", 4),
        1084: ("fixed", 4),
        1088: ("fixed", 4),
        1090: ("fixed", 4),
        1092: ("fixed", 4),
        1094: ("fixed", 4),
        1093: ("fixed", 4),
        1095: ("fixed", 8),
        1091: ("fixed", 8),
    }
    fields = []
    i = 16
    while i + 2 <= len(decoded):
        fid = int.from_bytes(decoded[i : i + 2], "big")
        if fid in field_widths:
            kind, size = field_widths[fid]
            if kind == "tlv":
                ln = int.from_bytes(decoded[i + 2 : i + 6], "big")
                fields.append((fid, decoded[i + 6 : i + 6 + ln]))
                i += 6 + ln
            else:
                fields.append((fid, decoded[i + 2 : i + 2 + size]))
                i += 2 + size
        elif (1051 <= fid <= 1073) or (1151 <= fid <= 1156):
            fields.append((fid, decoded[i + 2 : i + 3]))
            i += 3
        else:
            break
    return fields


# --------------------------------------------------------------- xxhash32


def test_xxhash32_known_values():
    assert xxh32_intdigest(b"") == 0x02CC5D05
    assert xxh32_intdigest(b"a") == 0x550D7456
    assert xxh32_intdigest(b"abc") == 0x32D153FF
    assert xxh32_digest("d") == bytes([0x42, 0xF3, 0x52, 0x90])


# -------------------------------------------------------------- aes round-trip


def test_aes_custom_round_trip():
    aes = AESCustomSBox()
    block = b"0123456789abcdef"
    enc = aes.encrypt_block(block)
    assert len(enc) == 16
    assert aes.decrypt_block(enc) == block


# ------------------------------------------------------------ end-to-end


class TestRapParamSigner:
    def test_outer_envelope_invariants(self):
        signer = RapParamSigner(rng=random.Random(42))
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {"num": 0})
        d = _decode(sig)
        assert d["mark"][0:3] == [7, 36, 1]
        assert 4 <= d["mark"][3] <= 6
        assert d["proto"] == 1
        assert d["key_len"] == 20
        assert d["sdk"] == 10201
        assert d["padding"] == [0] * 8
        assert d["cipher_len"] % 16 == 4

    def test_outer_xxhash_passes(self):
        signer = RapParamSigner()
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        d = _decode(sig)
        raw = base64.b64decode(sig)
        body_after_36 = raw[36:]
        assert xxh32_digest(body_after_36) == d["outer_xxhash"]

    def test_inner_payload_layout_matches_sdk_10201(self):
        signer = RapParamSigner()
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {"num": 0, "refresh_type": 1})
        d = _decode(sig)
        decoded = d["decoded_payload"]
        assert len(decoded) == 205, "expected 205-byte SDK 10201 payload"

        fields = _walk_fields(decoded)
        fids = [fid for fid, _ in fields]

        expected_order = (
            [1002, 1003]
            + list(range(1051, 1066))
            + [1070]
            + list(range(1066, 1070))
            + [1100]
            + [1071, 1072, 1073]
            + [1078, 1082, 1084, 1088, 1090]
            + [1092, 1094, 1095, 1093, 1091]
            + list(range(1151, 1157))
        )
        assert fids == expected_order

    def test_request_hash_matches_url_plus_body(self):
        signer = RapParamSigner()
        body = {"num": 0, "refresh_type": 1}
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", body)
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        expected = xxh32_digest('//edith.xiaohongshu.com/api/sns/web/v1/homefeed{"num":0,"refresh_type":1}')
        assert fields[1003] == expected

    def test_request_hash_for_get_excludes_body(self):
        signer = RapParamSigner()
        sig = signer.sign(
            "GET",
            "/api/sns/web/v1/user_posted?num=30",
            None,
        )
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        expected = xxh32_digest("//edith.xiaohongshu.com/api/sns/web/v1/user_posted?num=30")
        assert fields[1003] == expected

    def test_request_hash_matches_real_browser_capture(self):
        """Pinned to a real captured x-rap-param + matching curl URL+body."""
        url_path = "/api/sns/web/v1/feed"
        body = (
            '{"source_note_id":"69fa0d4e000000002003be0c",'
            '"image_formats":["jpg","webp","avif"],'
            '"extra":{"need_body_topic":"1"},'
            '"xsec_source":"pc_feed",'
            '"xsec_token":"ABKN_94weMpdGt2DcCVA_u5Ih0MTm4gNrNpA0eb50R3ms="}'
        )
        signer = RapParamSigner()
        sig = signer.sign("POST", url_path, body)
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        expected = xxh32_digest("//edith.xiaohongshu.com" + url_path + body)
        # 0x47f5fe45 — matches the captured x-rap-param byte-for-byte.
        assert expected.hex() == "47f5fe45"
        assert fields[1003] == expected

    def test_inner_timestamp_is_recent(self):
        before = int(time.time() * 1000)
        signer = RapParamSigner()
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        after = int(time.time() * 1000)
        d = _decode(sig)
        assert before <= d["inner_ts_ms"] <= after

    def test_page_load_timestamp_is_stable_across_calls(self):
        signer = RapParamSigner()
        sigs = [signer.sign("POST", "/api/sns/web/v1/homefeed", {"i": i}) for i in range(3)]
        page_loads = []
        for s in sigs:
            d = _decode(s)
            fields = dict(_walk_fields(d["decoded_payload"]))
            ts = int.from_bytes(fields[1095][2:8], "big")
            page_loads.append(ts)
        assert page_loads[0] == page_loads[1] == page_loads[2]

    def test_uuid_is_16_lowercase_alphanumeric(self):
        signer = RapParamSigner()
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        uuid_bytes = fields[1002]
        assert len(uuid_bytes) == 16
        uuid_str = uuid_bytes.decode("ascii")
        assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in uuid_str)

    def test_sign_cost_block_layout(self):
        signer = RapParamSigner(rng=random.Random(0))
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        sct = fields[1091]
        assert int.from_bytes(sct[0:4], "big") == 4
        assert sct[6:8] == b"\xff\xff"

    def test_window_dimensions_match_config(self):
        cfg = RapParamConfig().with_overrides(DEFAULT_INNER_WIDTH=1280, DEFAULT_INNER_HEIGHT=720)
        signer = RapParamSigner(config=cfg)
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        d = _decode(sig)
        fields = dict(_walk_fields(d["decoded_payload"]))
        assert int.from_bytes(fields[1092], "big") == 1280
        assert int.from_bytes(fields[1094], "big") == 720

    def test_xhshow_client_method_works(self):
        client = Xhshow()
        sig = client.sign_x_rap_param("POST", "/api/sns/web/v1/homefeed", {"num": 0})
        d = _decode(sig)
        assert d["sdk"] == 10201
        assert len(d["decoded_payload"]) == 205

    def test_xhshow_client_keeps_page_load_stable(self):
        client = Xhshow()
        s1 = client.sign_x_rap_param("POST", "/a", {})
        s2 = client.sign_x_rap_param("POST", "/b", {})
        d1 = _decode(s1)
        d2 = _decode(s2)
        f1 = dict(_walk_fields(d1["decoded_payload"]))
        f2 = dict(_walk_fields(d2["decoded_payload"]))
        ts1 = int.from_bytes(f1[1095][2:8], "big")
        ts2 = int.from_bytes(f2[1095][2:8], "big")
        assert ts1 == ts2

    def test_unique_uuids_across_calls(self):
        signer = RapParamSigner()
        uuids = set()
        for _ in range(20):
            sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
            d = _decode(sig)
            fields = dict(_walk_fields(d["decoded_payload"]))
            uuids.add(fields[1002])
        assert len(uuids) >= 18  # allow tiny chance of collision

    @pytest.mark.parametrize(
        "salt_seed",
        list(range(8)),
    )
    def test_salt_length_is_in_range(self, salt_seed: int):
        signer = RapParamSigner(rng=random.Random(salt_seed))
        sig = signer.sign("POST", "/api/sns/web/v1/homefeed", {})
        d = _decode(sig)
        assert 4 <= d["salt_len"] <= 6
        assert len(d["salt"]) == d["salt_len"]
