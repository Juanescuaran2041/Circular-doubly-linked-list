"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const CENTER = 300;
const RING_RADIUS = 220;
const AUTO_STEP_MS = 1000;

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
  selectionButtons: ["btn-attack", "btn-isolate", "btn-remove"].map((id) => document.getElementById(id)),
};

let state = null;
let selectedId = null;
let autoTimer = null;

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

/* ---------- Geometry helpers ---------- */

function seconds(ms) {
  return `${Math.ceil(ms / 1000)} s`;
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

/* ---------- Rendering ---------- */

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

function drawNode(node, index, total, size) {
  const { x, y } = pointAt(angleOf(index, total));
  const classes = ["node", node.state.toLowerCase()];
  if (node.id === selectedId) classes.push("selected");

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
  ui.ring.replaceChildren();

  const defs = svgElement("defs");
  addArrowMarker(defs, "head-next", "#9aa6c8");
  addArrowMarker(defs, "head-prev", "#8b5cf6");
  ui.ring.appendChild(defs);

  if (nodes.length === 0) {
    const empty = svgElement("text", { x: CENTER, y: CENTER, class: "center-line" });
    empty.textContent = "The ring is empty. Add a honeypot to start.";
    ui.ring.appendChild(empty);
    return;
  }

  drawLinks(nodes.length, size);
  nodes.forEach((node, index) => drawNode(node, index, nodes.length, size));
  drawCenter();
}

function renderRail() {
  ui.clock.textContent = seconds(state.now_ms);

  const node = state.honeypots.find((item) => item.id === selectedId);
  ui.selectedEmpty.hidden = Boolean(node);
  ui.selectedDetail.hidden = !node;
  ui.selectionButtons.forEach((button) => { button.disabled = !node; });
  if (node) {
    ui.selectedName.textContent = node.id;
    const attacks = `${node.attacks} of ${state.config.attack_threshold} attacks`;
    ui.selectedMeta.textContent = node.state === "ISOLATED"
      ? `Isolated, back in ${seconds(node.quarantine_left_ms)}`
      : `${node.state === "EXPOSED" ? "Exposed" : "Waiting"}, ${attacks}`;
  }
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
  renderRing();
  renderRail();
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
  send("/api/reset");
});

request("/api/state");
