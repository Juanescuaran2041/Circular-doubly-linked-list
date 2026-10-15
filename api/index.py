import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mtd_ring.api.server import make_handler  # noqa: E402
from mtd_ring.api.stateless import SESSION_BODY_BYTES, StatelessApi  # noqa: E402
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed  # noqa: E402

# One feed per warm instance caches the attacker list. Downloads run inline because a function
# can be frozen as soon as it answers, which would leave a background download unfinished.
feed = SansIscFeed(timeout_seconds=3, spawn=lambda task: task())
SharedHandler = make_handler(StatelessApi(feed), SESSION_BODY_BYTES)


# Vercel rewrites /api/<route> to /api?route=<route>; this restores the path the shared handler expects.
def restore_route(raw_path: str) -> str:
    parsed = urlparse(raw_path)
    route = parse_qs(parsed.query).get("route", [""])[0]
    if not route and parsed.path.startswith("/api/"):
        route = parsed.path[len("/api/"):]
    return "/api/" + route.strip("/")


# The entry point Vercel looks for.
class handler(SharedHandler):

    def do_GET(self) -> None:
        self.path = restore_route(self.path)
        super().do_GET()

    def do_POST(self) -> None:
        self.path = restore_route(self.path)
        super().do_POST()
