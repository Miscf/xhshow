"""x-s-common signature generation"""

import json
import random
import time
from typing import TYPE_CHECKING, Any

from ..config import CryptoConfig
from ..core.crc32_encrypt import CRC32
from ..generators.fingerprint import FingerprintGenerator
from ..utils.encoder import Base64Encoder

if TYPE_CHECKING:
    from ..session import SessionManager

__all__ = ["XsCommonSigner"]


class XsCommonSigner:
    """Generate x-s-common signatures"""

    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self._fp_generator = FingerprintGenerator(self.config)
        self._encoder = Base64Encoder(self.config)

    def sign(
        self,
        cookie_dict: dict[str, Any],
        session: "SessionManager | None" = None,
    ) -> str:
        """
        Generate x-s-common signature

        Args:
            cookie_dict: Cookie dictionary (must be dict, not string)
            session: Optional session manager. When provided, the page_load_timestamp
                and dsl_timestamp from the session populate ``x12``.

        Returns:
            x-s-common signature string

        Raises:
            KeyError: If 'a1' cookie is missing
        """
        a1_value = cookie_dict["a1"]
        is_logged_in = bool(cookie_dict.get("web_session"))

        fingerprint = self._fp_generator.generate(cookies=cookie_dict, user_agent=self.config.PUBLIC_USERAGENT)
        b1 = self._fp_generator.generate_b1(fingerprint)

        x9 = CRC32.crc32_js_int(b1)

        sign_struct = dict(self.config.SIGNATURE_XSCOMMON_TEMPLATE)
        sign_struct["x5"] = a1_value
        sign_struct["x8"] = b1 if is_logged_in else None
        sign_struct["x9"] = x9
        sign_struct["x12"] = self._build_x12(session, is_logged_in)

        sign_json = json.dumps(sign_struct, separators=(",", ":"), ensure_ascii=False)
        return self._encoder.encode(sign_json)

    def _build_x12(self, session: "SessionManager | None", is_logged_in: bool) -> str:
        """
        Build the ``x12`` field as ``"<page_load_ts>;<dsl_ts>"``.

        For guests (no web_session) the first segment is the literal ``"null"``,
        matching the real client behavior captured in samples.json.
        """
        if session is not None:
            dsl_ts = session.dsl_timestamp
            page_load_ts = session.page_load_timestamp
        else:
            now_ms = int(time.time() * 1000)
            dsl_ts = now_ms - random.randint(
                self.config.SESSION_DSL_OFFSET_MS_MIN,
                self.config.SESSION_DSL_OFFSET_MS_MAX,
            )
            page_load_ts = now_ms - random.randint(
                self.config.XSC_PAGE_LOAD_OFFSET_MS_MIN,
                self.config.XSC_PAGE_LOAD_OFFSET_MS_MAX,
            )

        first = str(page_load_ts) if is_logged_in else "null"
        return f"{first};{dsl_ts}"
