from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from typing import Any, Callable, List, Optional

from mtd_ring.threat_intel.attacker import Attacker

URL_TEMPLATE = "https://isc.sans.edu/api/topips/records/{limit}?json"
USER_AGENT = "MirageRing/1.0 (university data structures project)"
MAX_RESPONSE_BYTES = 1_000_000
RETRY_AFTER_FAILURE_SECONDS = 60

# Documentation-only addresses (RFC 5737), used when SANS ISC cannot be reached.
OFFLINE_SAMPLE = [
    Attacker("192.0.2.10", 90_000, 1),
    Attacker("192.0.2.77", 60_000, 1),
    Attacker("198.51.100.23", 45_000, 1),
    Attacker("198.51.100.141", 30_000, 1),
    Attacker("203.0.113.8", 20_000, 1),
    Attacker("203.0.113.200", 10_000, 1),
]


# Top attacking IPs reported to the SANS ISC DShield honeypot network, cached and with an offline fallback.
class SansIscFeed:

    def __init__(
        self,
        limit: int = 20,
        ttl_seconds: int = 3600,
        timeout_seconds: int = 5,
        fetch_json: Optional[Callable[[str], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._ttl_seconds = ttl_seconds
        self._timeout_seconds = timeout_seconds
        self._fetch_json = fetch_json or self._download_json
        self._clock = clock
        self._attackers: List[Attacker] = []
        self._live = False
        self._expires_at: Optional[float] = None

    # Describes where the current attackers come from, for the UI.
    @property
    def source(self) -> str:
        if self._live:
            return f"SANS ISC DShield, top {len(self._attackers)} attacking IPs"
        return "Offline sample (SANS ISC could not be reached)"

    # Returns the attackers, downloading them again only when the cache has expired.
    def attackers(self) -> List[Attacker]:
        now = self._clock()
        if self._expires_at is not None and now < self._expires_at:
            return self._attackers

        try:
            payload = self._fetch_json(URL_TEMPLATE.format(limit=self._limit))
            parsed = self._parse(payload)
            if not parsed:
                raise ValueError("empty response")
            self._attackers = parsed
            self._live = True
            self._expires_at = now + self._ttl_seconds
        except (OSError, ValueError, KeyError, TypeError):
            if not self._live:
                self._attackers = list(OFFLINE_SAMPLE)
            self._expires_at = now + RETRY_AFTER_FAILURE_SECONDS
        return self._attackers

    # Reads the JSON list from SANS ISC.
    def _download_json(self, url: str) -> Any:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
            return json.loads(response.read(MAX_RESPONSE_BYTES))

    # Turns the API payload into validated attackers, skipping malformed entries.
    @staticmethod
    def _parse(payload: Any) -> List[Attacker]:
        records = payload.values() if isinstance(payload, dict) else payload
        attackers: List[Attacker] = []
        for record in records:
            if not isinstance(record, dict) or "source" not in record:
                continue
            ip = SansIscFeed._normalize_ip(str(record["source"]))
            if ip is None:
                continue
            attackers.append(Attacker(ip, int(record.get("reports", 0)), int(record.get("targets", 0))))
        return attackers

    # SANS pads octets with zeros (e.g. 013.094.254.200); this returns a clean IPv4 or None.
    @staticmethod
    def _normalize_ip(raw: str) -> Optional[str]:
        try:
            octets = [str(int(part)) for part in raw.strip().split(".")]
            return str(ipaddress.IPv4Address(".".join(octets)))
        except ValueError:
            return None
