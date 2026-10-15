# Base class of every error raised by the ring and the controller.
class RingError(Exception):
    pass


# A honeypot id was used twice in the same ring.
class DuplicateHoneypotError(RingError):
    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"Duplicate honeypot id: {honeypot_id}")


# An operation referenced an id that is not in the ring.
class UnknownHoneypotError(RingError):
    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"Unknown honeypot: {honeypot_id}")


# A rotation direction other than 1 (forward) or -1 (backward) was requested.
class InvalidDirectionError(RingError):
    def __init__(self) -> None:
        super().__init__("direction must be 1 (forward) or -1 (backward)")


# An isolated honeypot was attacked, but isolated servers are not visible to the network.
class IsolatedHoneypotError(RingError):
    def __init__(self, honeypot_id: str) -> None:
        super().__init__(f"{honeypot_id} is isolated and cannot be attacked")


# The simulated clock was asked to go backward.
class NegativeTimeError(RingError):
    def __init__(self) -> None:
        super().__init__("time cannot go backward")
