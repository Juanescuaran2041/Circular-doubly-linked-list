from __future__ import annotations

from typing import Any, Dict, Optional

from mtd_ring.api.server import ApiError, RingApi
from mtd_ring.config import RingConfig
from mtd_ring.errors import RingError
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed

SESSION_KEY = "session"
SESSION_BODY_BYTES = 65_536


# The same API as RingApi, but it remembers nothing: the client sends the whole state with every request.
class StatelessApi:

    def __init__(self, feed: SansIscFeed, config: Optional[RingConfig] = None) -> None:
        self._feed = feed
        self._config = config or RingConfig()

    # A fresh simulation, for a client that has no state yet.
    def state(self) -> Dict[str, Any]:
        return self._run(None, lambda api: api.state())

    # Rebuilds the simulation from the client state, applies the action and returns the new state.
    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._run(body.get(SESSION_KEY), lambda api: api.post(path, body))

    # Builds temporary objects from the session, runs the action and attaches the updated session.
    def _run(self, session: Any, action: Any) -> Dict[str, Any]:
        controller = MTDController(self._config)
        simulator = ThreatSimulator(controller, self._feed)
        try:
            if session is not None:
                self._restore(controller, simulator, session)
            if simulator.enabled:
                self._feed.attackers()
            result = action(RingApi(controller, simulator))
        except RingError as error:
            raise ApiError(str(error), error.code, error.params) from error
        result[SESSION_KEY] = {"controller": controller.export_state(), "threats": simulator.export_state()}
        return result

    # Loads both parts of the session, reporting a malformed one as an invalid session.
    @staticmethod
    def _restore(controller: MTDController, simulator: ThreatSimulator, session: Any) -> None:
        if not isinstance(session, dict) or "controller" not in session or "threats" not in session:
            raise ApiError("session must contain controller and threats", "invalid_session")
        controller.restore_state(session["controller"])
        simulator.restore_state(session["threats"])
