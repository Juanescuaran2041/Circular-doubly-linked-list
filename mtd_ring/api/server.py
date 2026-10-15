from __future__ import annotations

import errno
import json
import mimetypes
import sys
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from mtd_ring.errors import RingError
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.sans_isc_feed import SansIscFeed

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
MAX_BODY_BYTES = 4096
MAX_TIME_STEP_MS = 600_000
PORT_ATTEMPTS = 20

# Windows can register .css or .js with the wrong type, which makes browsers reject the stylesheet.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}

# Port already in use, or refused by the system (reserved ranges on Windows).
PORT_UNAVAILABLE_ERRORS = {errno.EADDRINUSE, errno.EACCES, 10048, 10013}


# A client error that maps to an HTTP 400 response; the code and params let the client translate it.
class ApiError(Exception):

    def __init__(self, message: str, code: str = "bad_request", params: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.params = params or {}

    # Builds the JSON body of the error response.
    def to_dict(self) -> Dict[str, Any]:
        return {"error": str(self), "code": self.code, "params": self.params}


# Translates JSON requests into controller calls; the lock keeps it thread-safe.
class RingApi:

    def __init__(self, controller: MTDController, simulator: ThreatSimulator) -> None:
        self._controller = controller
        self._simulator = simulator
        self._lock = threading.Lock()
        self._routes: Dict[str, Callable[[Dict[str, Any]], None]] = {
            "/api/time": self._time,
            "/api/rotate": self._rotate,
            "/api/attack": self._attack,
            "/api/isolate": self._isolate,
            "/api/remove": self._remove,
            "/api/add": self._add,
            "/api/reset": self._reset,
            "/api/threats": self._threats,
        }

    def state(self) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot()

    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        action = self._routes.get(path)
        if action is None:
            raise KeyError(path)
        with self._lock:
            try:
                action(body)
            except RingError as error:
                raise ApiError(str(error), error.code, error.params) from error
            return self._snapshot()

    # The ring snapshot plus the threat simulator state.
    def _snapshot(self) -> Dict[str, Any]:
        snapshot = self._controller.snapshot()
        snapshot["threats"] = self._simulator.snapshot()
        return snapshot

    @staticmethod
    def _required(body: Dict[str, Any], key: str, kind: type) -> Any:
        value = body.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise ApiError(
                f"'{key}' is required and must be of type {kind.__name__}",
                "field_invalid",
                {"field": key, "type": kind.__name__},
            )
        return value

    def _time(self, body: Dict[str, Any]) -> None:
        ms = self._required(body, "ms", int)
        if ms < 0:
            raise ApiError("'ms' must not be negative", "negative_time")
        if ms > MAX_TIME_STEP_MS:
            raise ApiError(f"'ms' must not exceed {MAX_TIME_STEP_MS}", "time_too_large", {"max": MAX_TIME_STEP_MS})
        self._simulator.advance(ms)

    def _rotate(self, body: Dict[str, Any]) -> None:
        self._controller.rotate(body.get("direction", 1))

    def _attack(self, body: Dict[str, Any]) -> None:
        self._controller.register_attack(self._required(body, "id", str))

    def _isolate(self, body: Dict[str, Any]) -> None:
        self._controller.isolate(self._required(body, "id", str))

    def _remove(self, body: Dict[str, Any]) -> None:
        self._controller.remove(self._required(body, "id", str))

    def _add(self, body: Dict[str, Any]) -> None:
        self._controller.add_honeypot()

    def _reset(self, body: Dict[str, Any]) -> None:
        self._controller.reset()
        self._simulator.clear()

    def _threats(self, body: Dict[str, Any]) -> None:
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise ApiError(
                "'enabled' is required and must be a boolean", "field_invalid", {"field": "enabled", "type": "bool"}
            )
        if enabled:
            self._simulator.enable()
        else:
            self._simulator.disable()


def make_handler(api: RingApi) -> type:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            try:
                if self.path == "/api/state":
                    self._send_json(200, api.state())
                else:
                    self._send_static()
            except Exception:
                self._send_internal_error()

        def do_POST(self) -> None:
            try:
                body = self._read_body()
                self._send_json(200, api.post(self.path, body))
            except ApiError as error:
                self._send_json(400, error.to_dict())
            except KeyError:
                self._send_json(404, {"error": "unknown route", "code": "unknown_route", "params": {}})
            except Exception:
                self._send_internal_error()

        # Logs the traceback in the terminal and answers with JSON instead of dropping the connection.
        def _send_internal_error(self) -> None:
            traceback.print_exc()
            try:
                self._send_json(500, {"error": "internal error", "code": "internal_error", "params": {}})
            except OSError:
                pass

        def _read_body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                raise ApiError("request body too large", "body_too_large")
            if length == 0:
                return {}
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError as error:
                raise ApiError("invalid JSON", "invalid_json") from error
            if not isinstance(body, dict):
                raise ApiError("JSON body must be an object", "body_not_object")
            return body

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_static(self) -> None:
            relative = self.path.split("?", 1)[0].lstrip("/") or "index.html"
            target = (WEB_ROOT / relative).resolve()
            if WEB_ROOT not in target.parents or not target.is_file():
                self._send_json(404, {"error": "not found", "code": "not_found", "params": {}})
                return
            data = target.read_bytes()
            content_type = (
                CONTENT_TYPES.get(target.suffix.lower())
                or mimetypes.guess_type(target.name)[0]
                or "application/octet-stream"
            )
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return Handler


# Binds the first free port starting at `port`, because the preferred one may be taken or reserved.
def bind_server(api: RingApi, host: str, port: int, attempts: int = PORT_ATTEMPTS) -> Tuple[ThreadingHTTPServer, int]:
    last_error: Optional[OSError] = None
    for candidate in range(port, port + attempts):
        try:
            return ThreadingHTTPServer((host, candidate), make_handler(api)), candidate
        except OSError as error:
            if error.errno not in PORT_UNAVAILABLE_ERRORS:
                raise
            last_error = error
    raise OSError(f"No free port between {port} and {port + attempts - 1}") from last_error


def run(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    controller = MTDController()
    api = RingApi(controller, ThreatSimulator(controller, SansIscFeed()))
    try:
        server, actual_port = bind_server(api, host, port)
    except OSError as error:
        print(f"Could not start the server: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    url = f"http://{host}:{actual_port}"
    if actual_port != port:
        print(f"Port {port} is not available, using {actual_port} instead.")
    print(f"Mirage Ring is running at {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
