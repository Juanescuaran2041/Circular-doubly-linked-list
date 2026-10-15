from __future__ import annotations

from typing import Any, Dict, Optional

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
        # Only isolated nodes are skipped; WAITING and EXPOSED ones are usable.
        return self.state != HoneypotState.ISOLATED

    def is_exposed(self) -> bool:
        """True if this is the one server currently visible to the network."""
        return self.state == HoneypotState.EXPOSED

    def is_isolated(self) -> bool:
        """True if the node is in quarantine."""
        return self.state == HoneypotState.ISOLATED

    def expose(self) -> None:
        """Make this node the visible one. An isolated node cannot be exposed."""
        if self.is_isolated():
            raise ValueError(f"{self.id} is isolated and cannot be exposed")
        self.state = HoneypotState.EXPOSED

    def conceal(self) -> None:
        """Stop being visible. Only affects an exposed node, so a quarantine is never overwritten."""
        if self.is_exposed():
            self.state = HoneypotState.WAITING

    def quarantine_expired(self, now: int) -> bool:
        """True if the node is isolated and the clock has reached the end of its quarantine."""
        return (
            self.is_isolated()
            and self.quarantine_ends_at is not None
            and now >= self.quarantine_ends_at
        )

    def to_dict(self, now: int) -> Dict[str, Any]:
        """Serializable view of this node, as used in ``MTDController.snapshot()``."""
        return {
            "id": self.id,
            "state": self.state.value,
            "attacks": self.attacks,
            "quarantine_left_ms": self.quarantine_left(now),
        }

    def record_attack(self) -> int:
        """Increment the attack counter and return the new total."""
        # The node only counts; the controller decides if the total is "too many".
        self.attacks += 1
        return self.attacks

    def isolate(self, until: int) -> None:
        """Enter quarantine until the simulated clock reaches ``until``."""
        # Two facts describe a quarantine: the state and when it ends.
        self.state = HoneypotState.ISOLATED
        self.quarantine_ends_at = until

    def release(self) -> None:
        """Leave quarantine: back to WAITING with the attack counter cleared."""
        # Undo everything isolate() did and start with a clean record.
        self.state = HoneypotState.WAITING
        self.quarantine_ends_at = None
        self.attacks = 0

    def quarantine_left(self, now: int) -> Optional[int]:
        """Milliseconds of quarantine remaining, or ``None`` if not isolated."""
        if self.state != HoneypotState.ISOLATED or self.quarantine_ends_at is None:
            return None
        # Never negative: if the end time already passed, 0 ms are left.
        return max(0, self.quarantine_ends_at - now)

    def __repr__(self) -> str:
        return f"HoneypotNode({self.id!r}, {self.state.value})"
