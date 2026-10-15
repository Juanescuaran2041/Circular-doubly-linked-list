from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mtd_ring.errors import InvalidSessionError
from mtd_ring.honeypot_state import HoneypotState

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_VALUE = 10**12
MAX_ATTACKS = 1_000_000
MAX_HONEYPOTS = 200
MAX_EVENTS = 60
OUTCOMES = ("landed", "missed")


# Returns an integer inside the bounds; booleans are rejected because Python treats them as integers.
def require_int(value: Any, name: str, low: int = 0, high: int = MAX_VALUE) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise InvalidSessionError(f"'{name}' must be an integer between {low} and {high}")
    return value


# Returns a short identifier made only of letters, digits, underscores and hyphens.
def require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        raise InvalidSessionError(f"'{name}' must be a short identifier")
    return value


# Returns a dictionary, or fails with a session error.
def require_dict(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidSessionError(f"'{name}' must be an object")
    return value


# Returns a list that is not longer than the limit.
def require_list(value: Any, name: str, max_length: int) -> List[Any]:
    if not isinstance(value, list) or len(value) > max_length:
        raise InvalidSessionError(f"'{name}' must be a list of at most {max_length} items")
    return value


# Returns a boolean, rejecting other types.
def require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidSessionError(f"'{name}' must be true or false")
    return value


@dataclass(frozen=True)
class HoneypotData:
    id: str
    state: HoneypotState
    attacks: int
    quarantine_ends_at: Optional[int]


@dataclass(frozen=True)
class ControllerData:
    now: int
    next_rotation_at: int
    id_counter: int
    history: List[str]
    exposed: Optional[str]
    honeypots: List[HoneypotData]


@dataclass(frozen=True)
class ThreatEventData:
    id: int
    time_ms: int
    ip: str
    reports: int
    target: str
    outcome: str


@dataclass(frozen=True)
class ThreatData:
    enabled: bool
    next_id: int
    landed: int
    missed: int
    events: List[ThreatEventData]


# Validates one honeypot entry of the controller state.
def _parse_honeypot(item: Any) -> HoneypotData:
    entry = require_dict(item, "honeypot")
    try:
        state = HoneypotState(entry.get("state"))
    except (ValueError, TypeError):
        raise InvalidSessionError("'state' is not a known honeypot state") from None
    ends_at = entry.get("quarantine_ends_at")
    if ends_at is not None:
        ends_at = require_int(ends_at, "quarantine_ends_at")
    if (state is HoneypotState.ISOLATED) != (ends_at is not None):
        raise InvalidSessionError("only isolated honeypots have a quarantine end")
    return HoneypotData(
        require_id(entry.get("id"), "id"), state, require_int(entry.get("attacks"), "attacks", high=MAX_ATTACKS), ends_at
    )


# Validates the controller state sent by the client and turns it into trusted data.
def parse_controller_state(data: Any, history_limit: int) -> ControllerData:
    state = require_dict(data, "controller")
    honeypots = [_parse_honeypot(item) for item in require_list(state.get("honeypots"), "honeypots", MAX_HONEYPOTS)]

    ids = [honeypot.id for honeypot in honeypots]
    if len(set(ids)) != len(ids):
        raise InvalidSessionError("honeypot ids must be unique")

    exposed = state.get("exposed")
    if exposed is not None and require_id(exposed, "exposed") not in ids:
        raise InvalidSessionError("'exposed' must be one of the honeypots")
    marked = [honeypot.id for honeypot in honeypots if honeypot.state is HoneypotState.EXPOSED]
    if marked and marked != [exposed]:
        raise InvalidSessionError("exactly the exposed honeypot may be marked as exposed")

    history = [require_id(item, "history") for item in require_list(state.get("history"), "history", history_limit)]
    return ControllerData(
        now=require_int(state.get("now"), "now"),
        next_rotation_at=require_int(state.get("next_rotation_at"), "next_rotation_at"),
        id_counter=require_int(state.get("id_counter"), "id_counter"),
        history=history,
        exposed=exposed,
        honeypots=honeypots,
    )


# Validates one replayed attack of the threat simulator state.
def _parse_event(item: Any) -> ThreatEventData:
    entry = require_dict(item, "event")
    ip = entry.get("ip")
    try:
        ipaddress.IPv4Address(ip)
    except (ValueError, TypeError):
        raise InvalidSessionError("'ip' must be an IPv4 address") from None
    outcome = entry.get("outcome")
    if outcome not in OUTCOMES:
        raise InvalidSessionError("'outcome' must be landed or missed")
    return ThreatEventData(
        require_int(entry.get("id"), "id", low=1),
        require_int(entry.get("time_ms"), "time_ms"),
        ip,
        require_int(entry.get("reports"), "reports"),
        require_id(entry.get("target"), "target"),
        outcome,
    )


# Validates the threat simulator state sent by the client.
def parse_threat_state(data: Any) -> ThreatData:
    state = require_dict(data, "threats")
    events = [_parse_event(item) for item in require_list(state.get("events"), "events", MAX_EVENTS)]
    return ThreatData(
        enabled=require_bool(state.get("enabled"), "enabled"),
        next_id=require_int(state.get("next_id"), "next_id", low=1),
        landed=require_int(state.get("landed"), "landed"),
        missed=require_int(state.get("missed"), "missed"),
        events=events,
    )
