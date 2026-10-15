from __future__ import annotations

from typing import Optional

from mtd_ring.honeypot_state import HoneypotState


class HoneypotNode:
    """A decoy server and, at the same time, a node of the ring.

    It carries its own state (attacks, quarantine) and its two links.
    Invariant managed by ``HoneypotRing``: ``next`` and ``prev`` are never ``None``
    while the node belongs to a ring (a lone node points to itself).
    """

    def __init__(self, honeypot_id: str) -> None:
        self.id: str = honeypot_id
        self.state: HoneypotState = HoneypotState.WAITING
        self.attacks: int = 0
        self.quarantine_ends_at: Optional[int] = None  # simulated clock, in ms
        self.next: Optional[HoneypotNode] = None
        self.prev: Optional[HoneypotNode] = None

    def is_available(self) -> bool:
        """True if the rotation may expose this node (i.e. it is not isolated)."""
        raise NotImplementedError

    def record_attack(self) -> int:
        """Increment the attack counter and return the new total."""
        raise NotImplementedError

    def isolate(self, until: int) -> None:
        """Enter quarantine until the simulated clock reaches ``until``."""
        raise NotImplementedError

    def release(self) -> None:
        """Leave quarantine: back to WAITING with the attack counter cleared."""
        raise NotImplementedError

    def quarantine_left(self, now: int) -> Optional[int]:
        """Milliseconds of quarantine remaining, or ``None`` if not isolated."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"HoneypotNode({self.id!r}, {self.state.value})"
