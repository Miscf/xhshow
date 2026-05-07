import random
import time
from typing import NamedTuple

from .config import CryptoConfig


class SignState(NamedTuple):
    """Immutable state for a single signing operation."""

    page_load_timestamp: int
    sequence_value: int
    window_props_length: int
    uri_length: int


class SessionManager:
    """
    Manages the state for a simulated user session to generate more realistic signatures.

    This class maintains counters that should persist and evolve across multiple requests
    within the same logical session.
    """

    def __init__(self, config: CryptoConfig | None = None):
        self._config = config or CryptoConfig()
        now_ms = int(time.time() * 1000)
        self.page_load_timestamp: int = now_ms
        self.sequence_value: int = random.randint(
            self._config.SESSION_SEQUENCE_INIT_MIN,
            self._config.SESSION_SEQUENCE_INIT_MAX,
        )
        self.window_props_length: int = random.randint(
            self._config.SESSION_WINDOW_PROPS_INIT_MIN,
            self._config.SESSION_WINDOW_PROPS_INIT_MAX,
        )
        # dsl_timestamp mimics the SDK distribution timestamp embedded in
        # https://as.xiaohongshu.com/api/sec/v1/ds (different per session, stable
        # within a session). Used as the second segment of x-s-common.x12.
        self.dsl_timestamp: int = now_ms - random.randint(
            self._config.SESSION_DSL_OFFSET_MS_MIN,
            self._config.SESSION_DSL_OFFSET_MS_MAX,
        )

    def update_state(self):
        """
        Updates the session state to simulate user activity between requests.

        This method should be called before each signing operation.
        """
        self.sequence_value += random.randint(
            self._config.SESSION_SEQUENCE_STEP_MIN,
            self._config.SESSION_SEQUENCE_STEP_MAX,
        )
        self.window_props_length += random.randint(
            self._config.SESSION_WINDOW_PROPS_STEP_MIN,
            self._config.SESSION_WINDOW_PROPS_STEP_MAX,
        )

    def get_current_state(self, uri: str) -> SignState:
        """
        Get the current signing state for a request.

        This method automatically updates the session state counters and calculates
        the URI length from the provided URI string.

        Args:
            uri (str): The URI string for the current request.

        Returns:
            SignState: An immutable tuple with the current state for signing.
        """
        self.update_state()
        return SignState(
            page_load_timestamp=self.page_load_timestamp,
            sequence_value=self.sequence_value,
            window_props_length=self.window_props_length,
            uri_length=len(uri),
        )
