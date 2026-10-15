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
        if direction not in (1, -1):
            raise RingError("direction must be 1 (forward) or -1 (backward)")
        anchor = self._exposed
        if anchor is None:
            return

        candidate = anchor
        for _ in range(len(self._ring)):
            candidate = candidate.next if direction == 1 else candidate.prev
            if candidate is anchor and anchor.is_exposed():
                break
            if candidate.is_available():
                self._expose(candidate)
                return
        self._schedule_next_rotation()

    # Counts an attack, isolating the target at the threshold and rotating if it was exposed.
    def register_attack(self, honeypot_id: str) -> None:
        node = self._ring.get(honeypot_id)
        if node.is_isolated():
            raise RingError(f"{honeypot_id} is isolated and cannot be attacked")

        was_exposed = node.is_exposed()
        total = node.record_attack()
        if total >= self._config.attack_threshold:
            self._isolate_node(node)
        elif was_exposed:
            self.rotate(1)

    # Puts a honeypot in quarantine by hand.
    def isolate(self, honeypot_id: str) -> None:
        self._isolate_node(self._ring.get(honeypot_id))

    # Permanently removes a honeypot, moving the exposure first if it was the exposed one.
    def remove(self, honeypot_id: str) -> None:
        node = self._ring.get(honeypot_id)

        if node is self._exposed:
            if len(self._ring) > 1:
                self.rotate(1)
            if self._exposed is node:
                self._exposed = node.next if len(self._ring) > 1 else None

        self._ring.remove(honeypot_id)

    # Moves the simulated clock, running the due rotation and releasing finished quarantines.
    def advance_time(self, ms: int) -> None:
        if ms < 0:
            raise RingError("time cannot go backward")
        self._now += ms

        if len(self._ring) > 0 and self._now >= self._next_rotation_at:
            self.rotate(1)

        for node in self._ring:
            if node.quarantine_expired(self._now):
                node.release()

        if len(self._ring) > 0 and not self._has_exposed():
            self.rotate(1)

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

    # Starts the quarantine of a node and moves the exposure away if it was the exposed one.
    def _isolate_node(self, node: HoneypotNode) -> None:
        was_exposed = node.is_exposed()
        node.isolate(self._now + self._config.quarantine_ms)
        if was_exposed:
            self.rotate(1)

    # Tells if some node is currently exposed.
    def _has_exposed(self) -> bool:
        return self._exposed is not None and self._exposed.is_exposed()
