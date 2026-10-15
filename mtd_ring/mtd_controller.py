from __future__ import annotations

from typing import Any, Dict, List, Optional

from mtd_ring.config import RingConfig
from mtd_ring.errors import RingError
from mtd_ring.honeypot_node import HoneypotNode
from mtd_ring.honeypot_ring import HoneypotRing


# Moving Target Defense policy on top of the ring: rotation, attacks, quarantine and a simulated clock.
class MTDController:

    def __init__(self, config: Optional[RingConfig] = None) -> None:
        self._config = config or RingConfig()
        self._ring = HoneypotRing()
        self._exposed: Optional[HoneypotNode] = None
        self._now: int = 0
        self._next_rotation_at: int = 0
        self._history: List[str] = []
        self._id_counter: int = 0
        self.reset()

    # Restarts the simulation with the initial honeypots and the first one exposed.
    def reset(self) -> None:
        self._ring.clear()
        self._exposed = None
        self._now = 0
        self._history = []
        self._id_counter = 0
        for _ in range(self._config.initial_size):
            self.add_honeypot()

    # Adds a honeypot with a generated id; it becomes the exposed one if the ring was empty.
    def add_honeypot(self) -> str:
        self._id_counter += 1
        node = self._ring.append(f"HP-{self._id_counter}")
        if self._exposed is None:
            self._expose(node)
        return node.id

    # Moves the exposure to the next (1) or previous (-1) available honeypot.
    def rotate(self, direction: int = 1) -> None:
        raise NotImplementedError

    # Counts an attack, isolating the target at the threshold and rotating if it was exposed.
    def register_attack(self, honeypot_id: str) -> None:
        raise NotImplementedError

    # Puts a honeypot in quarantine by hand.
    def isolate(self, honeypot_id: str) -> None:
        raise NotImplementedError

    # Permanently removes a honeypot, moving the exposure first if it was the exposed one.
    def remove(self, honeypot_id: str) -> None:
        raise NotImplementedError

    # Moves the simulated clock, running the due rotation and releasing finished quarantines.
    def advance_time(self, ms: int) -> None:
        raise NotImplementedError

    # Builds the dictionary the frontend draws.
    def snapshot(self) -> Dict[str, Any]:
        raise NotImplementedError

    # Makes a node the exposed one, records it in the history and schedules the next rotation.
    def _expose(self, node: HoneypotNode) -> None:
        if self._exposed is not None:
            self._exposed.conceal()
        node.expose()
        self._exposed = node
        self._history.append(node.id)
        del self._history[: -self._config.history_limit]
        self._schedule_next_rotation()

    # Sets the clock value at which the automatic rotation is due.
    def _schedule_next_rotation(self) -> None:
        self._next_rotation_at = self._now + self._config.rotation_interval_ms

    # Tells if some node is currently exposed.
    def _has_exposed(self) -> bool:
        return self._exposed is not None and self._exposed.is_exposed()
