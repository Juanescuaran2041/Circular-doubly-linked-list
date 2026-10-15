import copy
import importlib.util
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from mtd_ring.api.server import ApiError, RingApi
from mtd_ring.api.stateless import SESSION_KEY, StatelessApi
from mtd_ring.config import RingConfig
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed

SAMPLE = [
    {"source": "13.94.254.200", "reports": 319739, "targets": 1},
    {"source": "194.224.249.214", "reports": 309508, "targets": 2},
]


def make_feed():
    return SansIscFeed(fetch_json=lambda url: SAMPLE, spawn=lambda task: task())


def without_session(response):
    return {key: value for key, value in response.items() if key != SESSION_KEY}


class StatelessApiTest(unittest.TestCase):
    def setUp(self):
        self.api = StatelessApi(make_feed())

    def test_a_fresh_state_comes_with_a_session(self):
        response = self.api.state()
        self.assertEqual(len(response["honeypots"]), RingConfig().initial_size)
        self.assertIn("controller", response[SESSION_KEY])
        self.assertIn("threats", response[SESSION_KEY])

    def test_it_matches_the_stateful_api_step_by_step(self):
        controller = MTDController()
        stateful = RingApi(controller, ThreatSimulator(controller, make_feed()))
        steps = [
            ("/api/attack", {"id": "HP-2"}),
            ("/api/rotate", {"direction": 1}),
            ("/api/isolate", {"id": "HP-4"}),
            ("/api/time", {"ms": 40_000}),
            ("/api/add", {}),
            ("/api/rotate", {"direction": -1}),
            ("/api/remove", {"id": "HP-1"}),
            ("/api/time", {"ms": 70_000}),
        ]
        session = None
        for path, body in steps:
            expected = stateful.post(path, dict(body))
            payload = dict(body, **({SESSION_KEY: session} if session else {}))
            response = self.api.post(path, payload)
            session = response[SESSION_KEY]
            self.assertEqual(without_session(response), expected, path)

    def test_a_post_without_a_session_starts_from_a_fresh_simulation(self):
        response = self.api.post("/api/rotate", {"direction": 1})
        self.assertEqual(response["exposed_id"], "HP-2")

    def test_the_replay_and_its_events_survive_between_requests(self):
        enabled = self.api.post("/api/threats", {"enabled": True})
        self.assertTrue(enabled["threats"]["enabled"])
        self.assertEqual(enabled["threats"]["source_kind"], "live")

        session = enabled[SESSION_KEY]
        total_landed = total_missed = 0
        with mock.patch("mtd_ring.simulation.threat_simulator.random.Random.random", return_value=0.0):
            for _ in range(3):
                response = self.api.post("/api/time", {"ms": 5000, SESSION_KEY: session})
                session = response[SESSION_KEY]
                total_landed = response["threats"]["landed"]
                total_missed = response["threats"]["missed"]
        self.assertGreater(total_landed + total_missed, 5)
        ids = [event["id"] for event in response["threats"]["events"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(ids)), len(ids))

    def test_sync_returns_the_same_state_without_changing_it(self):
        changed = self.api.post("/api/attack", {"id": "HP-3"})
        synced = self.api.post("/api/sync", {SESSION_KEY: changed[SESSION_KEY]})
        self.assertEqual(synced, changed)

    def test_reset_returns_a_fresh_session(self):
        first = self.api.post("/api/attack", {"id": "HP-3"})
        reset = self.api.post("/api/reset", {SESSION_KEY: first[SESSION_KEY]})
        self.assertTrue(all(node["attacks"] == 0 for node in reset["honeypots"]))
        self.assertEqual(reset["now_ms"], 0)

    def test_domain_errors_keep_their_code(self):
        with self.assertRaises(ApiError) as caught:
            self.api.post("/api/attack", {"id": "HP-99"})
        self.assertEqual(caught.exception.code, "unknown_honeypot")

    def test_unknown_routes_still_raise_key_error(self):
        with self.assertRaises(KeyError):
            self.api.post("/api/nope", {})

    def test_rejects_a_tampered_or_malformed_session(self):
        valid = self.api.state()[SESSION_KEY]
        tampered = copy.deepcopy(valid)
        tampered["controller"]["honeypots"][0]["attacks"] = "lots"
        for name, session in {
            "not an object": "oops",
            "missing parts": {"controller": valid["controller"]},
            "tampered field": tampered,
            "empty": {},
        }.items():
            with self.assertRaises(ApiError, msg=name) as caught:
                self.api.post("/api/rotate", {SESSION_KEY: session})
            self.assertEqual(caught.exception.code, "invalid_session", name)


def load_vercel_entry():
    path = Path(__file__).resolve().parents[1] / "api" / "index.py"
    spec = importlib.util.spec_from_file_location("vercel_entry", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def call(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.loads(error.read())


class VercelEntryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patcher = mock.patch.object(SansIscFeed, "_download_json", return_value=SAMPLE)
        cls.patcher.start()
        cls.entry = load_vercel_entry()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.entry.handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.patcher.stop()

    def test_routes_arrive_as_a_query_parameter_after_the_rewrite(self):
        status, state = call(self.base, "/api?route=state")
        self.assertEqual(status, 200)
        session = state[SESSION_KEY]

        status, rotated = call(self.base, "/api?route=rotate", {"direction": 1, SESSION_KEY: session})
        self.assertEqual(status, 200)
        self.assertEqual(rotated["exposed_id"], "HP-2")

    def test_the_plain_path_also_works(self):
        status, state = call(self.base, "/api/state")
        self.assertEqual(status, 200)
        self.assertIn(SESSION_KEY, state)

    def test_a_flow_across_separate_requests_keeps_its_state(self):
        _, state = call(self.base, "/api?route=state")
        session = state[SESSION_KEY]
        for _ in range(3):
            _, response = call(self.base, "/api?route=attack", {"id": "HP-3", SESSION_KEY: session})
            session = response[SESSION_KEY]
        self.assertEqual(next(n for n in response["honeypots"] if n["id"] == "HP-3")["state"], "ISOLATED")

    def test_errors_are_json_with_a_code(self):
        status, body = call(self.base, "/api?route=attack", {"id": "HP-99"})
        self.assertEqual((status, body["code"]), (400, "unknown_honeypot"))
        status, body = call(self.base, "/api?route=rotate", {SESSION_KEY: {"controller": 1, "threats": 2}})
        self.assertEqual((status, body["code"]), (400, "invalid_session"))
        status, body = call(self.base, "/api?route=nope", {})
        self.assertEqual((status, body["code"]), (404, "unknown_route"))

    def test_a_session_bigger_than_the_limit_is_refused(self):
        status, body = call(self.base, "/api?route=rotate", {SESSION_KEY: {"padding": "x" * 70_000}})
        self.assertEqual((status, body["code"]), (400, "body_too_large"))

    def test_the_replay_can_be_enabled_through_the_function(self):
        status, response = call(self.base, "/api?route=threats", {"enabled": True})
        self.assertEqual(status, 200)
        self.assertEqual(response["threats"]["source_kind"], "live")


if __name__ == "__main__":
    unittest.main()
