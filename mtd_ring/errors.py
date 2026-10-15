from typing import Any, Dict, Optional


# Base class of every error raised by the ring and the controller; `code` and `params` let a client translate it.
class RingError(Exception):
    code = "ring_error"

    def __init__(self, message: str, params: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.params: Dict[str, Any] = params or {}


# A honeypot id was used twice in the same ring.
class DuplicateHoneypotError(RingError):
    code = "duplicate_honeypot"

    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"Duplicate honeypot id: {honeypot_id}", {"id": honeypot_id})


# An operation referenced an id that is not in the ring.
class UnknownHoneypotError(RingError):
    code = "unknown_honeypot"

    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"Unknown honeypot: {honeypot_id}", {"id": honeypot_id})


# A rotation direction other than 1 (forward) or -1 (backward) was requested.
class InvalidDirectionError(RingError):
    code = "invalid_direction"

    def __init__(self) -> None:
        super().__init__("direction must be 1 (forward) or -1 (backward)")


# An isolated honeypot was attacked, but isolated servers are not visible to the network.
class IsolatedHoneypotError(RingError):
    code = "isolated_honeypot"

    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"{honeypot_id} is isolated and cannot be attacked", {"id": honeypot_id})


# The simulated clock was asked to go backward.
class NegativeTimeError(RingError):
    code = "negative_time"

    def __init__(self) -> None:
        super().__init__("time cannot go backward")
