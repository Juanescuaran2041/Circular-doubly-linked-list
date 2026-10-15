from __future__ import annotations

from typing import Any, Dict, Optional

from mtd_ring.honeypot_state import HoneypotState


# A decoy server that is also a node of the circular doubly linked list.
class HoneypotNode:

    def __init__(self, honeypot_id: str) -> None:
        self.id: str = honeypot_id
        self.state: HoneypotState = HoneypotState.WAITING
        self.attacks: int = 0
        self.quarantine_ends_at: Optional[int] = None
        self.next: Optional[HoneypotNode] = None
        self.prev: Optional[HoneypotNode] = None

    # Tells if the rotation may expose this node (it is not isolated).
    def is_available(self) -> bool:
        return self.state != HoneypotState.ISOLATED

    # Tells if this is the server currently visible to the network.
    def is_exposed(self) -> bool:
        return self.state == HoneypotState.EXPOSED

    # Tells if the node is in quarantine.
    def is_isolated(self) -> bool:
        return self.state == HoneypotState.ISOLATED

    # Makes this node the visible one; an isolated node cannot be exposed.
    def expose(self) -> None:
        if self.is_isolated():
            raise ValueError(f"{self.id} is isolated and cannot be exposed")
        self.state = HoneypotState.EXPOSED

    # Stops showing this node without overwriting a quarantine.
    def conceal(self) -> None:
        if self.is_exposed():
            self.state = HoneypotState.WAITING

    # Tells if the quarantine already reached its end time.
    def quarantine_expired(self, now: int) -> bool:
        return (
            self.is_isolated()
            and self.quarantine_ends_at is not None
            and now >= self.quarantine_ends_at
        )

    # Builds the dictionary the frontend receives for this node.
    def to_dict(self, now: int) -> Dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state.value,
            "attacks": self.attacks,
            "quarantine_left_ms": self.quarantine_left(now),
        }

    # Adds one attack to the counter and returns the new total.
    def record_attack(self) -> int:
        self.attacks += 1
        return self.attacks

    # Puts the node in quarantine until the given clock value.
    def isolate(self, until: int) -> None:
        self.state = HoneypotState.ISOLATED
        self.quarantine_ends_at = until

    # Ends the quarantine and clears the attack counter.
    def release(self) -> None:
        self.state = HoneypotState.WAITING
        self.quarantine_ends_at = None
        self.attacks = 0

    # Returns the milliseconds of quarantine left, or None if not isolated.
    def quarantine_left(self, now: int) -> Optional[int]:
        if self.state != HoneypotState.ISOLATED or self.quarantine_ends_at is None:
            return None
        return max(0, self.quarantine_ends_at - now)

    def __repr__(self) -> str:
        return f"HoneypotNode({self.id!r}, {self.state.value})"
