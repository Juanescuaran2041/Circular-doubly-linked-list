# Honeypot Ring with Moving Target Defense (MTD)

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
  errors.py                    # RingError
  honeypot_state.py            # HoneypotState enum (EXPOSED, WAITING, ISOLATED)
  honeypot_node.py             # HoneypotNode: a honeypot that is also a list node
  honeypot_ring.py             # HoneypotRing: the circular doubly linked list
  mtd_controller.py            # MTDController: rotation, attacks, quarantine, clock
  api/
    server.py                  # HTTP server (stdlib): JSON API + static files
web/
  index.html                   # page layout
  css/styles.css               # styles
  js/app.js                    # fetches the API and draws the SVG ring
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
# open http://127.0.0.1:8000
```

Tests:

```bash
python -m unittest discover -v
```

## Frontend

- Ring drawn in SVG: light arrow = `next`, dark arrow = `prev`.
- Colors: **red** exposed, **green** waiting, **dashed gray** isolated (with a quarantine countdown).
- Click a server to select it, then use **Attack**, **Isolate** or **Remove**.
- **Rotate →** and **← Step back** buttons, **+10 s** / **+30 s**, and an **Auto** mode.
- **Add honeypot** and **Reset**, plus a history of the most recently exposed servers.

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

Every POST returns the new snapshot. Errors return `400` with `{"error": "..."}`. The snapshot shape is documented in `MTDController.snapshot()`.

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

## Limitations

- This is a **simulation** of the scheduling logic: it does not change real IPs or ports. That would require SDN or firewall rules.
- A fixed interval is **predictable**: there is research showing that an AI-capable attacker can infer when an IP rotation is triggered. A simple improvement is to add random jitter to the interval.
- Every rotation has a resource cost, so rotating more often is not always better.

## Possible extensions

1. Random jitter on the rotation interval.
2. Port hopping in addition to server rotation.
3. A min-heap to schedule rotations per server with different intervals.
4. Persist the attack history and use it to calibrate the threshold.
