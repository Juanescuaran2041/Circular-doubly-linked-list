"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const CENTER = 300;
const RING_RADIUS = 220;
const AUTO_STEP_MS = 1000;
const FEED_LIMIT = 40;
const MAX_PIPS = 6;

const ui = {
  ring: document.getElementById("ring"),
  clock: document.getElementById("clock"),
  error: document.getElementById("error"),
  history: document.getElementById("history"),
  auto: document.getElementById("btn-auto"),
  selectedEmpty: document.getElementById("selected-empty"),
  selectedDetail: document.getElementById("selected-detail"),
  selectedName: document.getElementById("selected-name"),
  selectedMeta: document.getElementById("selected-meta"),
  selectedMeter: document.getElementById("selected-meter"),
  feed: document.getElementById("feed"),
  feedEmpty: document.getElementById("feed-empty"),
  statAttacks: document.getElementById("stat-attacks"),
  statRotations: document.getElementById("stat-rotations"),
  statIsolated: document.getElementById("stat-isolated"),
  statServers: document.getElementById("stat-servers"),
  selectionButtons: ["btn-attack", "btn-isolate", "btn-remove"].map((id) => document.getElementById(id)),
};

let state = null;
let selectedId = null;
let autoTimer = null;
let lastExposedId = null;
let activityResetPending = false;

const session = { attacks: 0, rotations: 0, feed: [], pendingHits: [] };

/* ---------- API ---------- */

// Calls the API (GET when there is no body, POST otherwise) and re-renders with the new snapshot.
async function request(path, body) {
  const options = body === undefined
    ? {}
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  try {
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) {
      showError(data.error || `Request failed (${response.status})`);
      return;
    }
    showError("");
    trackChanges(state, data);
    state = data;
    render();
  } catch (error) {
    showError("Cannot reach the server. Is `python main.py` running?");
  }
}

const send = (path, body = {}) => request(path, body);

function showError(message) {
  ui.error.textContent = message;
  ui.error.hidden = !message;
}

/* ---------- Activity derived from consecutive snapshots ---------- */

function logEvent(time, kind, text) {
  session.feed.unshift({ time, kind, text });
  session.feed.length = Math.min(session.feed.length, FEED_LIMIT);
}

function resetActivity() {
  session.attacks = 0;
  session.rotations = 0;
  session.feed = [];
  session.pendingHits = [];
  lastExposedId = null;
}

// Compares two snapshots and records what changed: attacks, rotations, quarantines and membership.
function trackChanges(previous, current) {
  const timeWentBack = previous && current.now_ms < previous.now_ms;
  if (activityResetPending || timeWentBack || !previous) {
    activityResetPending = false;
    resetActivity();
    return;
  }

  const time = current.now_ms;
  const before = new Map(previous.honeypots.map((node) => [node.id, node]));
  const after = new Map(current.honeypots.map((node) => [node.id, node]));

  for (const [id, node] of after) {
    const old = before.get(id);
    if (!old) {
      logEvent(time, "ring", `${id} joined the ring`);
      continue;
    }
    if (node.attacks > old.attacks) {
      session.attacks += node.attacks - old.attacks;
      session.pendingHits.push(id);
      logEvent(time, "attack", `${id} was attacked (${node.attacks} of ${current.config.attack_threshold})`);
    }
    if (node.state === "ISOLATED" && old.state !== "ISOLATED") {
      logEvent(time, "isolate", `${id} moved to quarantine`);
    }
    if (old.state === "ISOLATED" && node.state !== "ISOLATED") {
      logEvent(time, "release", `${id} left quarantine`);
    }
  }
  for (const id of before.keys()) {
    if (!after.has(id)) logEvent(time, "ring", `${id} was removed`);
  }
  if (current.exposed_id && current.exposed_id !== previous.exposed_id) {
    session.rotations += 1;
    logEvent(time, "rotate", `Exposure moved from ${previous.exposed_id || "nowhere"} to ${current.exposed_id}`);
  }
}

/* ---------- Geometry helpers ---------- */

function seconds(ms) {
  return `${Math.ceil(ms / 1000)} s`;
}

function clockText(ms) {
  const total = Math.floor(ms / 1000);
  const minutes = String(Math.floor(total / 60)).padStart(2, "0");
  return `${minutes}:${String(total % 60).padStart(2, "0")}`;
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

function angleOf(index, total) {
  return (2 * Math.PI * index) / total - Math.PI / 2;
}

function pointAt(angle, radius = RING_RADIUS) {
  return { x: CENTER + radius * Math.cos(angle), y: CENTER + radius * Math.sin(angle) };
}

function nodeSize(total) {
  return Math.max(24, 42 - Math.max(0, total - 8) * 2);
}

// Pointy-top hexagon, echoing the shape used in the logo.
function hexagonPoints(cx, cy, radius) {
  return Array.from({ length: 6 }, (_, k) => {
    const a = -Math.PI / 2 + (k * Math.PI) / 3;
    return `${cx + radius * Math.cos(a)},${cy + radius * Math.sin(a)}`;
  }).join(" ");
}

// Circular arc between two angles; `clockwise` picks the drawing direction.
function arcPath(from, to, radius, clockwise) {
  const start = pointAt(from, radius);
  const end = pointAt(to, radius);
  return `M ${start.x} ${start.y} A ${radius} ${radius} 0 0 ${clockwise ? 1 : 0} ${end.x} ${end.y}`;
}

function addArrowMarker(defs, id, color) {
  const marker = svgElement("marker", {
    id, viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto",
  });
  marker.appendChild(svgElement("path", { d: "M 0 1 L 9 5 L 0 9 z", fill: color }));
  defs.appendChild(marker);
}

/* ---------- Ring rendering ---------- */

function drawOrbits() {
  ui.ring.appendChild(svgElement("circle", { cx: CENTER, cy: CENTER, r: RING_RADIUS + 62, class: "orbit outer" }));
  ui.ring.appendChild(svgElement("circle", { cx: CENTER, cy: CENTER, r: RING_RADIUS - 74, class: "orbit inner" }));
}

function drawLinks(total, size) {
  if (total < 2) return;
  const gap = (size + 10) / RING_RADIUS;
  for (let i = 0; i < total; i += 1) {
    const from = angleOf(i, total) + gap;
    const to = angleOf(i + 1, total) - gap;
    ui.ring.appendChild(svgElement("path", {
      d: arcPath(from, to, RING_RADIUS + 10, true), class: "arc-next", "marker-end": "url(#head-next)",
    }));
    ui.ring.appendChild(svgElement("path", {
      d: arcPath(to, from, RING_RADIUS - 10, false), class: "arc-prev", "marker-end": "url(#head-prev)",
    }));
  }
}

// Sweeps a glowing stroke along the ring from the previous exposed server to the new one.
function drawTrail(nodes) {
  const exposedId = state.exposed_id;
  const previousId = lastExposedId;
  lastExposedId = exposedId;
  if (!previousId || !exposedId || previousId === exposedId) return;

  const from = nodes.findIndex((node) => node.id === previousId);
  const to = nodes.findIndex((node) => node.id === exposedId);
  if (from < 0 || to < 0) return;

  const total = nodes.length;
  const forward = (to - from + total) % total <= total / 2;
  ui.ring.appendChild(svgElement("path", {
    d: arcPath(angleOf(from, total), angleOf(to, total), RING_RADIUS, forward),
    class: "trail",
    pathLength: 1,
  }));
}

// A slow ripple leaving the exposed server.
function drawRipple(node, index, total, size) {
  if (!node.state || node.state !== "EXPOSED") return;
  const { x, y } = pointAt(angleOf(index, total));
  ui.ring.appendChild(svgElement("polygon", { points: hexagonPoints(x, y, size), class: "ripple" }));
}

// A red beam coming from outside the ring and striking an attacked server.
function drawBeam(index, total, size) {
  const angle = angleOf(index, total);
  const start = pointAt(angle, RING_RADIUS + 150);
  const end = pointAt(angle, RING_RADIUS + size + 6);
  ui.ring.appendChild(svgElement("path", {
    d: `M ${start.x} ${start.y} L ${end.x} ${end.y}`, class: "beam", pathLength: 1,
  }));
}

function drawThreatPips(node, x, y, size, threshold) {
  const count = Math.min(threshold, MAX_PIPS);
  const spacing = 10;
  const startX = x - ((count - 1) * spacing) / 2;
  const filled = Math.min(node.attacks, count);
  for (let i = 0; i < count; i += 1) {
    ui.ring.appendChild(svgElement("circle", {
      cx: startX + i * spacing, cy: y + size + 12, r: 3, class: `threat-pip${i < filled ? " on" : ""}`,
    }));
  }
}

function drawNode(node, index, total, size, struck) {
  const { x, y } = pointAt(angleOf(index, total));
  const classes = ["node", node.state.toLowerCase()];
  if (node.id === selectedId) classes.push("selected");
  if (struck) classes.push("hit");

  const group = svgElement("g", {
    class: classes.join(" "), tabindex: 0, role: "button",
    "aria-label": `${node.id}, ${node.state.toLowerCase()}${node.id === selectedId ? ", selected" : ""}`,
  });
  group.appendChild(svgElement("polygon", { points: hexagonPoints(x, y, size), class: "node-shape" }));

  const label = svgElement("text", { x, y: y - 1, class: "node-id" });
  label.textContent = node.id;
  const detail = svgElement("text", { x, y: y + 15, class: "node-sub" });
  detail.textContent = node.state === "ISOLATED" ? seconds(node.quarantine_left_ms) : `${node.attacks} hits`;
  group.append(label, detail);

  const toggleSelection = () => {
    selectedId = node.id === selectedId ? null : node.id;
    render();
  };
  group.addEventListener("click", toggleSelection);
  group.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleSelection();
    }
  });
  ui.ring.appendChild(group);

  if (node.state !== "ISOLATED") drawThreatPips(node, x, y, size, state.config.attack_threshold);
}

function drawCenter() {
  const title = svgElement("text", { x: CENTER, y: CENTER + 8, class: "center-id" });
  title.textContent = state.exposed_id || "No target";
  const caption = svgElement("text", { x: CENTER, y: CENTER + 40, class: "center-line" });
  caption.textContent = state.exposed_id
    ? `exposed, moves in ${seconds(state.next_rotation_in_ms)}`
    : "nothing is exposed right now";
  ui.ring.append(title, caption);
}

function renderRing() {
  const nodes = state.honeypots;
  const size = nodeSize(nodes.length);
  const struck = new Set(session.pendingHits);
  ui.ring.replaceChildren();

  const defs = svgElement("defs");
  addArrowMarker(defs, "head-next", "#9aa6c8");
  addArrowMarker(defs, "head-prev", "#8b5cf6");
  ui.ring.appendChild(defs);
  drawOrbits();

  if (nodes.length === 0) {
    const empty = svgElement("text", { x: CENTER, y: CENTER, class: "center-line" });
    empty.textContent = "The ring is empty. Add a honeypot to start.";
    ui.ring.appendChild(empty);
    return;
  }

  drawLinks(nodes.length, size);
  nodes.forEach((node, index) => drawRipple(node, index, nodes.length, size));
  drawTrail(nodes);
  nodes.forEach((node, index) => {
    if (struck.has(node.id)) drawBeam(index, nodes.length, size);
    drawNode(node, index, nodes.length, size, struck.has(node.id));
  });
  drawCenter();
  session.pendingHits = [];
}

/* ---------- Side panels ---------- */

function renderStats() {
  ui.statAttacks.textContent = session.attacks;
  ui.statRotations.textContent = session.rotations;
  ui.statIsolated.textContent = state.honeypots.filter((node) => node.state === "ISOLATED").length;
  ui.statServers.textContent = state.honeypots.length;
}

function renderSelected() {
  const node = state.honeypots.find((item) => item.id === selectedId);
  ui.selectedEmpty.hidden = Boolean(node);
  ui.selectedDetail.hidden = !node;
  ui.selectionButtons.forEach((button) => { button.disabled = !node; });
  if (!node) return;

  ui.selectedName.textContent = node.id;
  if (node.state === "ISOLATED") {
    ui.selectedMeta.textContent = `Isolated, back in ${seconds(node.quarantine_left_ms)}`;
    ui.selectedMeter.style.width = `${(node.quarantine_left_ms / state.config.quarantine_ms) * 100}%`;
    ui.selectedMeter.style.background = "var(--amber)";
  } else {
    const label = node.state === "EXPOSED" ? "Exposed" : "Waiting";
    ui.selectedMeta.textContent = `${label}, ${node.attacks} of ${state.config.attack_threshold} attacks`;
    ui.selectedMeter.style.width = `${Math.min(100, (node.attacks / state.config.attack_threshold) * 100)}%`;
    ui.selectedMeter.style.background = "var(--rose)";
  }
}

function renderFeed() {
  ui.feedEmpty.hidden = session.feed.length > 0;
  ui.feed.replaceChildren(...session.feed.map((entry) => {
    const item = document.createElement("li");
    item.className = entry.kind;
    const time = document.createElement("time");
    time.textContent = clockText(entry.time);
    const text = document.createElement("span");
    text.textContent = entry.text;
    item.append(time, text);
    return item;
  }));
}

function renderHistory() {
  ui.history.replaceChildren(...state.history.map((id) => {
    const item = document.createElement("li");
    const stop = document.createElement("span");
    stop.className = "stop";
    stop.textContent = id;
    item.appendChild(stop);
    return item;
  }));
  ui.history.scrollLeft = ui.history.scrollWidth;
}

function render() {
  if (!state) return;
  if (selectedId && !state.honeypots.some((node) => node.id === selectedId)) selectedId = null;
  ui.clock.textContent = clockText(state.now_ms);
  renderRing();
  renderStats();
  renderSelected();
  renderFeed();
  renderHistory();
}

/* ---------- Controls ---------- */

function toggleAuto() {
  const enabled = autoTimer === null;
  if (enabled) {
    autoTimer = setInterval(() => send("/api/time", { ms: AUTO_STEP_MS }), AUTO_STEP_MS);
  } else {
    clearInterval(autoTimer);
    autoTimer = null;
  }
  ui.auto.setAttribute("aria-pressed", String(enabled));
}

function bind(id, handler) {
  document.getElementById(id).addEventListener("click", handler);
}

bind("btn-rotate", () => send("/api/rotate", { direction: 1 }));
bind("btn-back", () => send("/api/rotate", { direction: -1 }));
bind("btn-time-10", () => send("/api/time", { ms: 10000 }));
bind("btn-time-30", () => send("/api/time", { ms: 30000 }));
bind("btn-auto", toggleAuto);
bind("btn-attack", () => selectedId && send("/api/attack", { id: selectedId }));
bind("btn-isolate", () => selectedId && send("/api/isolate", { id: selectedId }));
bind("btn-remove", () => selectedId && send("/api/remove", { id: selectedId }));
bind("btn-add", () => send("/api/add"));
bind("btn-reset", () => {
  selectedId = null;
  activityResetPending = true;
  send("/api/reset");
});

request("/api/state");
