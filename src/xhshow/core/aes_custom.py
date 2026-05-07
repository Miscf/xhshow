"""AES-128 with a custom S-box, used by the x-rap-param algorithm.

Block layout follows standard AES-128 (10 rounds, 128-bit key, MixColumns matrix
unchanged) but the S-box is replaced. Mode is plain ECB; the wrapping protocol
adds an additional XOR-with-IV step on top of ECB.
"""

from __future__ import annotations

__all__ = ["AESCustomSBox", "RAP_AES_KEY", "RAP_CUSTOM_SBOX"]


# fmt: off
RAP_CUSTOM_SBOX: tuple[int, ...] = (
    122, 1, 88, 224, 80, 78, 2, 121, 29, 75, 83, 218, 107, 72, 212, 82,
    237, 119, 18, 33, 20, 21, 236, 16, 24, 229, 185, 241, 12, 8, 252, 125,
    249, 205, 181, 200, 230, 55, 38, 135, 86, 186, 184, 43, 173, 240, 104, 247,
    139, 141, 211, 94, 54, 77, 46, 146, 49, 130, 242, 41, 112, 61, 45, 215,
    182, 64, 178, 67, 68, 128, 120, 210, 13, 73, 74, 9, 99, 108, 7, 58,
    158, 213, 6, 198, 225, 98, 244, 52, 36, 89, 169, 87, 42, 0, 62, 23,
    44, 10, 26, 66, 250, 147, 190, 220, 245, 179, 106, 19, 232, 3, 199, 151,
    187, 115, 118, 134, 227, 70, 114, 71, 208, 5, 76, 56, 124, 31, 129, 171,
    117, 81, 235, 243, 50, 116, 17, 143, 132, 137, 156, 113, 34, 126, 157, 207,
    63, 145, 105, 101, 60, 109, 150, 162, 152, 153, 51, 57, 154, 202, 195, 159,
    160, 188, 228, 163, 164, 84, 127, 167, 168, 4, 111, 93, 172, 183, 39, 175,
    176, 40, 65, 174, 180, 110, 11, 27, 223, 142, 48, 177, 254, 144, 97, 96,
    192, 203, 92, 14, 239, 22, 131, 234, 32, 233, 201, 85, 196, 69, 133, 204,
    30, 170, 103, 138, 123, 53, 214, 25, 216, 217, 194, 219, 148, 221, 28, 222,
    166, 255, 248, 191, 91, 90, 15, 231, 193, 189, 209, 102, 197, 37, 238, 140,
    226, 95, 136, 161, 59, 165, 246, 206, 149, 47, 100, 35, 251, 253, 79, 155,
)
# fmt: on


RAP_AES_KEY: bytes = b"kqI1DTcwKX90ZtAy"


def _build_inverse_sbox(sbox: tuple[int, ...]) -> tuple[int, ...]:
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return tuple(inv)


_RCON: tuple[int, ...] = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(x: int) -> int:
    x = (x << 1) & 0x1FF
    return (x ^ 0x1B) & 0xFF if x & 0x100 else x & 0xFF


def _gf_mul(x: int, y: int) -> int:
    res = 0
    for _ in range(8):
        if y & 1:
            res ^= x
        high = x & 0x80
        x = (x << 1) & 0xFF
        if high:
            x ^= 0x1B
        y >>= 1
    return res


class AESCustomSBox:
    """AES-128 / ECB with a configurable S-box.

    The constructor takes the forward S-box; the inverse is derived. Both
    ``encrypt_block`` and ``decrypt_block`` operate on a single 16-byte block.
    """

    __slots__ = ("_sbox", "_inv_sbox", "_round_keys")

    def __init__(self, key: bytes = RAP_AES_KEY, sbox: tuple[int, ...] = RAP_CUSTOM_SBOX) -> None:
        if len(key) != 16:
            raise ValueError("key must be 16 bytes")
        if len(sbox) != 256:
            raise ValueError("sbox must be 256 entries")
        self._sbox = sbox
        self._inv_sbox = _build_inverse_sbox(sbox)
        self._round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> list[bytes]:
        w: list[list[int]] = [list(key[i : i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            t = w[i - 1].copy()
            if i % 4 == 0:
                t = [self._sbox[b] for b in (t[1:] + t[:1])]
                t[0] ^= _RCON[(i // 4) - 1]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        return [bytes(b for word in w[i : i + 4] for b in word) for i in range(0, 44, 4)]

    @staticmethod
    def _add_round_key(state: list[int], rk: bytes) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    def _sub_bytes(self, state: list[int]) -> None:
        for i in range(16):
            state[i] = self._sbox[state[i]]

    def _inv_sub_bytes(self, state: list[int]) -> None:
        for i in range(16):
            state[i] = self._inv_sbox[state[i]]

    @staticmethod
    def _shift_rows(state: list[int]) -> None:
        s = state.copy()
        state[1], state[5], state[9], state[13] = s[5], s[9], s[13], s[1]
        state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
        state[3], state[7], state[11], state[15] = s[15], s[3], s[7], s[11]

    @staticmethod
    def _inv_shift_rows(state: list[int]) -> None:
        s = state.copy()
        state[1], state[5], state[9], state[13] = s[13], s[1], s[5], s[9]
        state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
        state[3], state[7], state[11], state[15] = s[7], s[11], s[15], s[3]

    @staticmethod
    def _mix_columns(state: list[int]) -> None:
        for c in range(4):
            i = c * 4
            a = state[i : i + 4]
            state[i] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            state[i + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            state[i + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            state[i + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)

    @staticmethod
    def _inv_mix_columns(state: list[int]) -> None:
        for c in range(4):
            i = c * 4
            a = state[i : i + 4]
            state[i] = _gf_mul(a[0], 14) ^ _gf_mul(a[1], 11) ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9)
            state[i + 1] = _gf_mul(a[0], 9) ^ _gf_mul(a[1], 14) ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13)
            state[i + 2] = _gf_mul(a[0], 13) ^ _gf_mul(a[1], 9) ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11)
            state[i + 3] = _gf_mul(a[0], 11) ^ _gf_mul(a[1], 13) ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        state = list(block)
        rk = self._round_keys
        self._add_round_key(state, rk[0])
        for r in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rk[r])
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, rk[10])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        state = list(block)
        rk = self._round_keys
        self._add_round_key(state, rk[10])
        for r in range(9, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, rk[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, rk[0])
        return bytes(state)
