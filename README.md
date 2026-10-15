# Mirage Ring: Honeypot Ring with Moving Target Defense (MTD)

<p align="center"><img src="web/assets/logo.png" alt="Mirage Ring logo" width="160"></p>

Case study of a **circular doubly linked list** (Data Structures course), applied to cybersecurity.
Implemented in **Python** (standard library only) with a **web frontend** (HTML + CSS, plus a small JS file to draw the ring) that shows the ring in real time.

## Description

A set of decoy servers (honeypots) forms a ring. **Only one is exposed to the network at a time**, and the exposure rotates continuously, so the information an attacker gathers during reconnaissance quickly becomes stale. If the exposed server is attacked, the rotation happens immediately, and servers that accumulate too many attacks are put in quarantine.

## Background: Moving Target Defense

MTD is a proactive defense strategy: instead of protecting a static system, it periodically changes the attack surface. At the network level, the most common techniques are IP hopping, port hopping and migrating services between virtual machines. A common scheme uses a long rotation interval by default and rotates immediately when an attack is suspected, which is exactly the policy implemented in this case. Static honeypots are easy to fingerprint, and rotating which one is exposed helps address that problem.

## System rules

1. Every `rotation_interval_ms` (30 s by default) the exposure moves to the next server in the ring.
2. If the exposed server is attacked, the rotation is **immediate**.
3. A server that reaches `attack_threshold` attacks (3 by default) is **isolated** (quarantined) and the rotation skips it.
4. When the quarantine ends (`quarantine_ms`, 60 s by default) the server goes back to the ring.
5. You can **step back** to the previous server (rollback) if a rotation caused problems.
6. A permanently compromised server is **removed** from the ring in O(1).

## Why a circular doubly linked list?

| Feature | What it solves |
|---|---|
| **Circular** | The rotation never ends: the last node is followed by the first, so there is no `None` to handle. |
| **Doubly linked** (`prev`) | Enables backward rollback and removing a known node in O(1) by linking its neighbors. |
| **Node as a reference** | With an index of id → node, isolating and removing nodes needs no traversal. |

With an array you would have to reindex on removal and use modulo arithmetic on every move.

## Project structure

```
main.py                        # entry point: starts the web server
mtd_ring/
  config.py                    # RingConfig (intervals, thresholds)
  errors.py                    # RingError and its specific subclasses
  honeypot_state.py            # HoneypotState enum (EXPOSED, WAITING, ISOLATED)
  honeypot_node.py             # HoneypotNode: a honeypot that is also a list node
  honeypot_ring.py             # HoneypotRing: the circular doubly linked list
  mtd_controller.py            # MTDController: rotation, attacks, quarantine, clock
  threat_intel/
    attacker.py                # Attacker: an IP and its report volume
    sans_isc_feed.py           # SansIscFeed: top attacking IPs from SANS ISC DShield
  simulation/
    threat_event.py            # ThreatEvent: one replayed attack
    threat_simulator.py        # ThreatSimulator: replays real attackers while time runs
  api/
    server.py                  # HTTP server (stdlib): JSON API + static files
web/
  index.html                   # page layout
  css/styles.css               # styles
  js/i18n.js                   # English and Spanish dictionaries and the t() helper
  js/app.js                    # fetches the API and draws the SVG ring
  assets/                      # logo and favicon
tests/
  test_honeypot_ring.py        # structure tests
  test_mtd_controller.py       # policy tests
```

### Responsibilities (OOP)

- `HoneypotNode`: one server and one list node. Owns its state, its attack counter, its quarantine and its `next`/`prev` links.
- `HoneypotRing`: the data structure. Only knows how to link and unlink nodes; it has no policy.
- `MTDController`: the defense policy. Uses the ring, owns the simulated clock and produces the `snapshot()` the frontend draws.
- `RingApi`: translates HTTP/JSON into controller calls (with a lock, since the server is multi-threaded).

## How to run

Requires Python 3.9 or higher. There are no dependencies to install.

```bash
python main.py
```

The server prints its address and opens the browser. Options:

| Option | Effect |
|---|---|
| `--port 9000` | Preferred port (default `8000`) |
| `--host 127.0.0.1` | Address to listen on |
| `--no-browser` | Do not open the browser automatically |

If the preferred port is taken, or Windows reserves it, the server uses the next free one and says so in the terminal. Always open the address it prints.

### If something does not work

- **The page does not open:** use the exact address printed in the terminal. Opening `web/index.html` directly from the file explorer does not work because the page needs the server.
- **The page looks unstyled or old:** stop any other `python main.py` that is still running, start it again and reload the page with `Ctrl+F5`.
- **The Real attackers switch stays on "loading":** the server could not reach `isc.sans.edu` yet. It keeps trying in the background and falls back to an offline sample after the timeout, so nothing else freezes.
- **An error says the server hit an unexpected error:** the full traceback is printed in the terminal where `python main.py` is running.

Tests:

```bash
python -m unittest discover -v
```

## Frontend

- Dark interface built around the logo palette: cyan for the exposed server, violet for `prev` links, amber for isolated servers.
- The ring is drawn in SVG with hexagon nodes. The exposed server is shown in the center with a countdown to the next rotation.
- Every rotation plays a single glowing trail from the previous exposed server to the new one (disabled when the user prefers reduced motion).
- Click a server (or focus it and press Enter) to select it, then use **Attack**, **Isolate** or **Remove**.
- **Rotate** and **Step back**, **Wait 10 s** / **Wait 30 s**, and **Run automatically**.
- **Add honeypot** and **Reset simulation**, plus a timeline of the most recently exposed servers.
- **EN / ES** switch for the interface language, and a sun/moon icon for the light and dark themes. Both choices are remembered; the first visit follows the browser.

The clock is **simulated** (controlled by the server), so the demo is reproducible and does not depend on real time.

## Server states

| State | Meaning | Transition |
|---|---|---|
| `EXPOSED` | The only one visible to the network | → `WAITING` on rotation; → `ISOLATED` when the attack threshold is reached |
| `WAITING` | In the ring, ready to be exposed | → `EXPOSED` when its turn comes |
| `ISOLATED` | In quarantine, skipped by the rotation | → `WAITING` when the quarantine ends |

## Operations and complexity

| Operation | Cost | Note |
|---|---|---|
| `add_honeypot` | O(1) | Inserts at the end (`head.prev`) |
| `rotate` | O(1) typical, O(n) worst case | Worst case: skips many isolated nodes |
| `register_attack` | O(1) + rotation | Rotates only if the attacked server is the exposed one |
| `isolate` | O(1) + rotation | The node stays in the ring |
| `remove` | O(1) | Unlinks the node with no search |
| `advance_time` | O(n) | Checks quarantines; a min-heap would reduce it to O(log n) per event |

## REST API

| Method | Route | Body | Effect |
|---|---|---|---|
| GET | `/api/state` | — | Snapshot of the ring |
| POST | `/api/time` | `{"ms": 10000}` | Advances the clock |
| POST | `/api/rotate` | `{"direction": 1}` or `-1` | Rotates forward or backward |
| POST | `/api/attack` | `{"id": "HP-1"}` | Registers an attack |
| POST | `/api/isolate` | `{"id": "HP-1"}` | Immediate quarantine |
| POST | `/api/remove` | `{"id": "HP-1"}` | Permanent removal |
| POST | `/api/add` | — | Adds a honeypot |
| POST | `/api/reset` | — | Resets the simulation |
| POST | `/api/threats` | `{"enabled": true}` | Turns the real attacker replay on or off |

Every response is the ring snapshot plus a `threats` object (`enabled`, `source`, `landed`, `missed` and the latest `events`).
Every POST returns the new snapshot. Errors return `400` with `{"error": "...", "code": "...", "params": {...}}`. The snapshot shape is documented in `MTDController.snapshot()`.

## Languages

The interface is available in English and Spanish. Texts live in `web/js/i18n.js`; the page marks translatable elements with `data-i18n`, and code that builds text at runtime calls `t(key, params)`.

- The server never sends display text to translate: errors carry a stable `code` plus `params` (for example `unknown_honeypot` with `{"id": "HP-3"}`), and the threat feed reports `source_kind` and `source_count`. The English `error` message stays as a fallback.
- The activity feed stores translation keys and values, not finished sentences, so existing entries change language together with the rest of the page.
- To add a language, add a dictionary with the same keys to `TRANSLATIONS`, list its code in `SUPPORTED_LANGUAGES` and add a button with `data-lang` to the header.

## Design decisions

- **Isolate vs. remove:** isolating is temporary and the node stays in the ring; removing is permanent and the node leaves.
- **Rotation anchor:** it may end up pointing to an isolated node, and that is intentional, because the rotation needs a reference point to search from.
- **Size cap when searching for a candidate:** avoids the classic infinite loop of circular lists when every node is isolated.
- **Time as a parameter:** the logic never reads the system clock, so it is deterministic and testable without waiting.
- **One rotation per `advance_time` call:** even if more than one interval has passed, only one rotation happens.

## Edge cases covered by the tests

Empty ring, single node (points to itself), removing head, middle and only node, full rotation cycle, attack on the exposed server, isolation threshold, end of quarantine, all nodes isolated (no infinite loop, and recovery), rollback wrapping around the other end, removing the exposed server, removing the only node and adding again, duplicate id and unknown id.

## Other data structures applicable to MTD

The circular list solves **who is exposed**. Other MTD problems call for other structures:

| Problem | Structure | Why |
|---|---|---|
| Mapping real IP to virtual IP | Hash table (`dict`) in both directions | O(1) translation per packet |
| Picking new IPs or ports without repeats | Set of free values + FIFO expiry queue | Taking one is O(1); with a fixed TTL they expire in order |
| Scheduling each host's next hop | Min-heap by timestamp | Extracting the next event in O(log n) |
| Topology and route mutation | Graph (adjacency list) | Alternative routes with BFS or Dijkstra |
| Client blacklist | Hash set (IPs) and trie (CIDR ranges) | O(1) membership or prefix lookup |
| Detecting scans to trigger a rotation | Circular buffer with a sliding window | Bounded memory, analyzes only recent events |
| History to undo configurations | Stack | Natural LIFO for multi-step rollback |

## Real attacker data (SANS ISC)

The **Replay real attackers** switch feeds the simulation with the top attacking IPs reported to the
[SANS Internet Storm Center](https://isc.sans.edu/) DShield honeypot network (`/api/topips`, no API key).

- While time advances, the simulator launches attacks second by second. Attackers are picked in proportion to their report volume.
- Most attacks hit the exposed server and go through `register_attack`, so they can trigger rotation and quarantine.
- Some attacks aim at the server that was exposed **before** the last rotation. They are counted as **missed by rotation** and never reach the controller: this is the Moving Target Defense benefit made visible.
- The list is cached for one hour. If SANS ISC cannot be reached, the simulation falls back to a small sample of documentation-range addresses (RFC 5737) and says so in the interface.
- Only the IP and the report volume are real. The target server and the timing of each attack are simulated, and no traffic is sent to those addresses.

## Limitations

- This is a **simulation** of the scheduling logic: it does not change real IPs or ports. That would require SDN or firewall rules.
- A fixed interval is **predictable**: there is research showing that an AI-capable attacker can infer when an IP rotation is triggered. A simple improvement is to add random jitter to the interval.
- Every rotation has a resource cost, so rotating more often is not always better.

## Possible extensions

1. Random jitter on the rotation interval.
2. Port hopping in addition to server rotation.
3. A min-heap to schedule rotations per server with different intervals.
4. Persist the attack history and use it to calibrate the threshold.
