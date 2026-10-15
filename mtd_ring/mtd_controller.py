from __future__ import annotations

from typing import Any, Dict, Optional

from mtd_ring.config import RingConfig
from mtd_ring.honeypot_node import HoneypotNode
from mtd_ring.honeypot_ring import HoneypotRing


class MTDController:
    """Moving Target Defense policy on top of a ``HoneypotRing``.

    Time is a simulated clock owned by this object (``_now``, in ms) that only
    moves through ``advance_time``; the logic never reads the system clock.

    Suggested internal state: ``_ring``, ``_exposed`` (rotation anchor, which may
    point to an isolated node on purpose), ``_next_rotation_at``, ``_history``
    and a counter used to generate ids (``HP-1``, ``HP-2``...).
    """

    def __init__(self, config: Optional[RingConfig] = None) -> None:
        self._config = config or RingConfig()
        self._ring = HoneypotRing()
        self._exposed: Optional[HoneypotNode] = None
        self._now: int = 0
        self.reset()

    def reset(self) -> None:
        """Restart with ``config.initial_size`` honeypots, the first one exposed."""
        raise NotImplementedError

    def add_honeypot(self) -> str:
        """Append a honeypot with an auto-generated id and return it.

        If the ring was empty, the new honeypot becomes the exposed one.
        """
        raise NotImplementedError

    def rotate(self, direction: int = 1) -> None:
        """Expose the next (``1``) or previous (``-1``) available honeypot.

        Skip isolated nodes, capping the search at ``len(ring)`` steps so a ring
        with every node isolated cannot loop forever. Raise ``RingError`` on a bad
        direction. Record the history and reschedule the next automatic rotation.
        """
        raise NotImplementedError

    def register_attack(self, honeypot_id: str) -> None:
        """Count an attack. Isolate the target on reaching ``attack_threshold``;
        rotate immediately if the target was the exposed server."""
        raise NotImplementedError

    def isolate(self, honeypot_id: str) -> None:
        """Quarantine a honeypot for ``quarantine_ms``. It stays in the ring."""
        raise NotImplementedError

    def remove(self, honeypot_id: str) -> None:
        """Permanently remove a honeypot. Rotate first if it was the exposed one."""
        raise NotImplementedError

    def advance_time(self, ms: int) -> None:
        """Move the clock, release finished quarantines and run at most one rotation."""
        raise NotImplementedError

    def snapshot(self) -> Dict[str, Any]:
        """Serializable view consumed by the frontend.

        Shape::

            {
              "now_ms": int,
              "exposed_id": str | None,
              "next_rotation_in_ms": int | None,
              "config": {"rotation_interval_ms": int, "attack_threshold": int,
                         "quarantine_ms": int},
              "honeypots": [   # ring order, starting at the ring head
                {"id": str, "state": "EXPOSED|WAITING|ISOLATED",
                 "attacks": int, "quarantine_left_ms": int | None}
              ],
              "history": [str, ...]   # most recent last
            }
        """
        raise NotImplementedError
