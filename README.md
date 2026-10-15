# Honeypot Ring with Moving Target Defense (MTD)

Case study of a **circular doubly linked list** (Data Structures course), applied to cybersecurity.
Implemented in **Python** (standard library only) with a **web frontend** that draws the ring in real time.

> Code identifiers, file names and the UI text are in Spanish (e.g. `agregar`, `rotar`, `intervalo_ms`). This README uses the real names so you can find them in the code.

## Description

A set of decoy servers (honeypots) forms a ring. **Only one is exposed to the network at a time**, and the exposure rotates continuously, so the information an attacker gathers during reconnaissance quickly becomes stale. If the exposed server is attacked, the rotation happens immediately, and servers that accumulate too many attacks are put in quarantine.

## Background: Moving Target Defense

MTD is a proactive defense strategy: instead of protecting a static system, it periodically changes the attack surface. At the network level, the most common techniques are IP hopping, port hopping and migrating services between virtual machines. A common scheme uses a long rotation interval by default and rotates immediately when an attack is suspected, which is exactly the policy implemented in this case. Static honeypots are easy to fingerprint, and rotating which one is exposed helps address that problem.

## System rules

1. Every `intervalo_ms` (30 s by default) the exposure moves to the next server in the ring.
2. If the exposed server is attacked, the rotation is **immediate**.
3. A server that reaches `umbral_ataques` attacks (3 by default) is **isolated** (quarantined) and the rotation skips it.
4. When the quarantine ends (`cuarentena_ms`, 60 s by default) the server goes back to the ring.
5. You can **step back** to the previous server (rollback) if a rotation caused problems.
6. A permanently compromised server is **removed** from the ring in O(1).

## Why a circular doubly linked list?

| Feature | What it solves |
|---|---|
| **Circular** | The rotation never ends: the last node is followed by the first, so there is no `None` to handle. |
| **Doubly linked** (`prev`) | Enables backward rollback and removing a known node in O(1) by linking its neighbors. |
| **Node as a reference** | With a `dict` of id → node, isolating and removing nodes needs no traversal. |

With an array you would have to reindex on removal and use modulo arithmetic on every move.

## Project structure

```
lista_circular_doble.py   # generic structure (Nodo + ListaCircularDoble)
anillo_mtd.py             # domain logic: states, rotation, attacks, quarantine
servidor.py               # HTTP server (stdlib): JSON API + serves the frontend
index.html                # frontend: SVG ring, controls and history
test_anillo.py            # unit tests (unittest)
```

## How to run

Requires Python 3.9 or higher. There are no dependencies to install.

```bash
python servidor.py
# open http://localhost:8000
```

Tests:

```bash
python -m unittest -v
```

## Frontend

- Ring drawn in SVG: light arrow = `next`, dark arrow = `prev`.
- Colors: **red** exposed, **green** waiting, **dashed gray** isolated (with a quarantine countdown).
- Click a server to select it, then use **Atacar** (attack), **Aislar** (isolate) or **Retirar** (remove).
- **Rotar →** (rotate) and **← Retroceder** (step back) buttons, **+10 s** / **+30 s**, and an **Auto** mode.
- **Agregar honeypot** (add) and **Reiniciar** (reset), plus a history of the most recently exposed servers.

The clock is **simulated** (controlled by the server), so the demo is reproducible and does not depend on real time.

## Server states

| State | Meaning | Transition |
|---|---|---|
| `EXPUESTO` (exposed) | The only one visible to the network | → `EN_ESPERA` on rotation; → `AISLADO` when the attack threshold is reached |
| `EN_ESPERA` (waiting) | In the ring, ready to be exposed | → `EXPUESTO` when its turn comes |
| `AISLADO` (isolated) | In quarantine, skipped by the rotation | → `EN_ESPERA` when the quarantine ends |

## Operations and complexity

| Operation | Cost | Note |
|---|---|---|
| `agregar` | O(1) | Inserts at the end (`head.prev`) |
| `rotar` | O(1) typical, O(n) worst case | Worst case: skips many isolated nodes |
| `registrar_ataque` | O(1) + rotation | Rotates only if the attacked server is the exposed one |
| `aislar` | O(1) + rotation | The node stays in the ring |
| `retirar` | O(1) | `eliminar(nodo)` with no search |
| `tick` | O(n) | Checks quarantines; a min-heap would reduce it to O(log n) per event |

## REST API

| Method | Route | Body | Effect |
|---|---|---|---|
| GET | `/api/estado` | — | Snapshot of the ring |
| POST | `/api/tiempo` | `{"ms": 10000}` | Advances the clock and runs `tick` |
| POST | `/api/rotar` | `{"sentido": 1}` or `-1` | Rotates forward or backward |
| POST | `/api/atacar` | `{"id": "HP-1"}` | Registers an attack |
| POST | `/api/aislar` | `{"id": "HP-1"}` | Immediate quarantine |
| POST | `/api/retirar` | `{"id": "HP-1"}` | Permanent removal |
| POST | `/api/agregar` | — | Adds a honeypot |
| POST | `/api/reiniciar` | — | Resets the simulation |

Errors return `400` with `{"error": "..."}`.

## Design decisions

- **Isolate vs. remove:** isolating is temporary and the node stays in the ring; removing is permanent and the node leaves.
- **Rotation anchor (`_expuesto`):** it may end up pointing to an isolated node, and that is intentional, because the rotation needs a reference point to search from.
- **`size` cap when searching for a candidate:** avoids the classic infinite loop of circular lists when every node is isolated.
- **Time as a parameter (`ahora`):** the logic never reads the system clock, so it is deterministic and testable without waiting.
- **One `tick` per call:** even if more than one interval has passed, only one rotation happens.

## Edge cases covered by the tests

Empty list, single node (points to itself), removing head, middle and only node, full rotation cycle, attack on the exposed server, isolation threshold, end of quarantine, all nodes isolated (no infinite loop, and recovery), rollback wrapping around the other end, removing the exposed server, removing the only node and adding again, duplicate id and unknown id.

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

## References

- Patent, *Moving target defense systems and methods*: https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11902320
- *A Cost-effective Shuffling Method against DDoS Attacks using Moving Target Defense*: https://arxiv.org/pdf/1903.10102
- *Using a Combination of Shuffling and Diversity Moving Target Defense Techniques*: https://distantreader.org/stacks/journals/etasr/etasr-4417.pdf
- *Random Host and Service Multiplexing for MTD in SDN* (ICC 2019): https://utoronto.academia.edu/DilliSharma
- *MTDSense: AI-Based Fingerprinting of MTD Techniques in SDN*: https://arxiv.org/html/2408.03758v1
- *Risk-Based & Honeypot-Informed MTD* (poster, University of Waterloo): https://uwaterloo.ca/cybersecurity-privacy-institute/sites/default/files/uploads/documents/poster-30.pdf
- *Dynamic Honeypot Deployment in SDN*: https://journal.uod.ac/index.php/uodjournal/article/download/3367/1916/
- *A Survey of Moving Target Defenses for Network Security*: https://arxiv.org/pdf/1905.00964
