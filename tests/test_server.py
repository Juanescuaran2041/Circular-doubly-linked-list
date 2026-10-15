import json
import mimetypes
import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from mtd_ring.api.server import RingApi, bind_server, make_handler
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed


def make_api():
    controller = MTDController()
    feed = SansIscFeed(fetch_json=lambda url: [], spawn=lambda task: None)
    return RingApi(controller, ThreatSimulator(controller, feed))


# Starts the real HTTP handler on a free port for the duration of a test.
class RunningServer:
    def __init__(self, api):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(api))
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.headers.get("Content-Type"), response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.headers.get("Content-Type"), error.read()


class StartupTest(unittest.TestCase):
    def test_bind_server_skips_a_port_that_is_already_taken(self):
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        taken = blocker.getsockname()[1]
        try:
            server, actual = bind_server(make_api(), "127.0.0.1", taken)
            server.server_close()
            self.assertGreater(actual, taken)
        finally:
            blocker.close()

    def test_bind_server_reports_when_every_port_is_taken(self):
        with mock.patch("mtd_ring.api.server.ThreadingHTTPServer", side_effect=OSError(10048, "in use")):
            with self.assertRaises(OSError):
                bind_server(make_api(), "127.0.0.1", 8000, attempts=3)


class ServingTest(unittest.TestCase):
    def test_serves_the_page_and_its_assets_with_the_right_types(self):
        with RunningServer(make_api()) as running:
            expected = {
                "/": "text/html",
                "/css/styles.css": "text/css",
                "/js/app.js": "text/javascript",
                "/js/i18n.js": "text/javascript",
                "/assets/logo.png": "image/png",
            }
            for path, content_type in expected.items():
                status, header, body = fetch(running.url + path)
                self.assertEqual(status, 200, path)
                self.assertTrue(header.startswith(content_type), f"{path}: {header}")
                self.assertTrue(body, path)

    def test_a_wrong_system_registration_does_not_break_the_stylesheet(self):
        original = mimetypes.types_map.get(".css")
        mimetypes.types_map[".css"] = "text/plain"
        try:
            with RunningServer(make_api()) as running:
                _, header, _ = fetch(running.url + "/css/styles.css")
        finally:
            mimetypes.types_map[".css"] = original
        self.assertTrue(header.startswith("text/css"), header)

    def test_does_not_serve_files_outside_the_web_folder(self):
        with RunningServer(make_api()) as running:
            status, _, _ = fetch(running.url + "/../README.md")
            self.assertEqual(status, 404)

    def test_an_unexpected_error_returns_json_instead_of_dropping_the_connection(self):
        api = make_api()
        with mock.patch.object(api, "state", side_effect=RuntimeError("boom")):
            with RunningServer(api) as running:
                with mock.patch("traceback.print_exc"):
                    status, header, body = fetch(running.url + "/api/state")
        self.assertEqual(status, 500)
        self.assertTrue(header.startswith("application/json"))
        self.assertEqual(json.loads(body)["code"], "internal_error")

    def test_enabling_the_replay_answers_immediately_with_a_loading_state(self):
        api = make_api()
        with RunningServer(api) as running:
            request = urllib.request.Request(
                running.url + "/api/threats", data=json.dumps({"enabled": True}).encode(), method="POST"
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                threats = json.loads(response.read())["threats"]
        self.assertTrue(threats["enabled"])
        self.assertEqual(threats["source_kind"], "loading")


if __name__ == "__main__":
    unittest.main()
