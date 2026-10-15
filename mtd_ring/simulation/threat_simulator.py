from __future__ import annotations

import random
from collections import deque
from typing import Any, Deque, Dict, Optional

from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_event import LANDED, MISSED, ThreatEvent
from mtd_ring.threat_intel.attacker import Attacker
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed

STEP_MS = 1000
EVENT_LIMIT = 60
EVENTS_SENT = 30


# Replays real attacking IPs against the ring while the simulated clock advances.
class ThreatSimulator:

    def __init__(
        self,
        controller: MTDController,
        feed: SansIscFeed,
        rng: Optional[random.Random] = None,
        attack_chance: float = 0.25,
        stale_chance: float = 0.35,
    ) -> None:
        self._controller = controller
        self._feed = feed
        self._rng = rng or random.Random()
        self._attack_chance = attack_chance
        self._stale_chance = stale_chance
        self._enabled = False
        self._events: Deque[ThreatEvent] = deque(maxlen=EVENT_LIMIT)
        self._next_id = 1
        self._landed = 0
        self._missed = 0

    # Starts generating attacks and loads the attacker list.
    def enable(self) -> None:
        self._feed.attackers()
        self._enabled = True

    # Stops generating attacks.
    def disable(self) -> None:
        self._enabled = False

    # Forgets the events and totals, for when the simulation restarts.
    def clear(self) -> None:
        self._events.clear()
        self._landed = 0
        self._missed = 0

    # Advances the clock second by second, launching attacks along the way when enabled.
    def advance(self, ms: int) -> None:
        if ms <= 0 or not self._enabled:
            self._controller.advance_time(ms)
            return

        remaining = ms
        while remaining > 0:
            step = min(STEP_MS, remaining)
            self._controller.advance_time(step)
            remaining -= step
            if step == STEP_MS and self._rng.random() < self._attack_chance:
                self._launch_attack()

    # Builds the dictionary sent to the frontend.
    def snapshot(self) -> Dict[str, Any]:
        source_kind, source_count = self._feed.status
        return {
            "enabled": self._enabled,
            "source": self._feed.source,
            "source_kind": source_kind,
            "source_count": source_count,
            "landed": self._landed,
            "missed": self._missed,
            "events": [event.to_dict() for event in list(self._events)[-EVENTS_SENT:]],
        }

    # Sends one attack at the exposed server, or at one that has already rotated away.
    def _launch_attack(self) -> None:
        state = self._controller.snapshot()
        exposed_id = state["exposed_id"]
        attackers = self._feed.attackers()
        if exposed_id is None or not attackers:
            return

        attacker = self._rng.choices(attackers, weights=[a.reports for a in attackers])[0]
        stale_id = self._stale_target(state, exposed_id)

        if stale_id is not None and self._rng.random() < self._stale_chance:
            self._record(state["now_ms"], attacker, stale_id, MISSED)
            self._missed += 1
        else:
            self._controller.register_attack(exposed_id)
            self._record(state["now_ms"], attacker, exposed_id, LANDED)
            self._landed += 1

    # Finds the server that was exposed before the current one and is still in the ring.
    @staticmethod
    def _stale_target(state: Dict[str, Any], exposed_id: str) -> Optional[str]:
        in_ring = {node["id"] for node in state["honeypots"]}
        for honeypot_id in reversed(state["history"]):
            if honeypot_id != exposed_id and honeypot_id in in_ring:
                return honeypot_id
        return None

    # Stores an event with the next sequential id.
    def _record(self, time_ms: int, attacker: Attacker, target: str, outcome: str) -> None:
        self._events.append(ThreatEvent(self._next_id, time_ms, attacker.ip, attacker.reports, target, outcome))
        self._next_id += 1
