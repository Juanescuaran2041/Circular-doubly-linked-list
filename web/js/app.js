"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const CENTER = 250;
const RING_RADIUS = 175;
const NODE_RADIUS = 38;
const AUTO_STEP_MS = 1000;

const ui = {
  ring: document.getElementById("ring"),
  clock: document.getElementById("clock"),
  exposed: document.getElementById("exposed"),
  nextRotation: document.getElementById("next-rotation"),
  selected: document.getElementById("selected"),
  error: document.getElementById("error"),
  history: document.getElementById("history"),
  auto: document.getElementById("btn-auto"),
  selectionButtons: ["btn-attack", "btn-isolate", "btn-remove"].map((id) => document.getElementById(id)),
};

let state = null;
let selectedId = null;
let autoTimer = null;

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
    showError("Cannot reach the server");
  }
}

const send = (path, body = {}) => request(path, body);

function showError(message) {
  ui.error.textContent = message;
  ui.error.hidden = !message;
}

function seconds(ms) {
  return `${Math.ceil(ms / 1000)} s`;
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

function position(index, total) {
  const angle = (2 * Math.PI * index) / total - Math.PI / 2;
  return { x: CENTER + RING_RADIUS * Math.cos(angle), y: CENTER + RING_RADIUS * Math.sin(angle) };
}

/* Curved arrow between two ring positions; `side` offsets next vs prev so they do not overlap. */
function linkPath(from, to, side) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  const ux = dx / length;
  const uy = dy / length;
  const start = { x: from.x + ux * NODE_RADIUS, y: from.y + uy * NODE_RADIUS };
  const end = { x: to.x - ux * (NODE_RADIUS + 4), y: to.y - uy * (NODE_RADIUS + 4) };
  const bend = 14 * side;
  const control = { x: (start.x + end.x) / 2 - uy * bend, y: (start.y + end.y) / 2 + ux * bend };
  return `M ${start.x} ${start.y} Q ${control.x} ${control.y} ${end.x} ${end.y}`;
}

function addMarker(defs, id, color) {
  const marker = svgElement("marker", {
    id, viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse",
  });
  marker.appendChild(svgElement("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: color }));
  defs.appendChild(marker);
}

function renderRing() {
  const nodes = state.honeypots;
  ui.ring.replaceChildren();

  const defs = svgElement("defs");
  addMarker(defs, "arrow-next", "#9fb3c8");
  addMarker(defs, "arrow-prev", "#2d3b4e");
  ui.ring.appendChild(defs);

  if (nodes.length === 0) {
    const text = svgElement("text", { x: CENTER, y: CENTER, class: "center-text" });
    text.textContent = "The ring is empty";
    ui.ring.appendChild(text);
    return;
  }

  const points = nodes.map((_, index) => position(index, nodes.length));

  if (nodes.length > 1) {
    nodes.forEach((_, index) => {
      const nextIndex = (index + 1) % nodes.length;
      ui.ring.appendChild(svgElement("path", {
        d: linkPath(points[index], points[nextIndex], 1), class: "link-next", "marker-end": "url(#arrow-next)",
      }));
      ui.ring.appendChild(svgElement("path", {
        d: linkPath(points[nextIndex], points[index], 1), class: "link-prev", "marker-end": "url(#arrow-prev)",
      }));
    });
  }

  nodes.forEach((node, index) => {
    const { x, y } = points[index];
    const classes = ["node-group", node.state.toLowerCase()];
    if (node.id === selectedId) classes.push("selected");
    const group = svgElement("g", { class: classes.join(" "), tabindex: 0, role: "button", "aria-label": `${node.id}, ${node.state}` });
    group.appendChild(svgElement("circle", { cx: x, cy: y, r: NODE_RADIUS, class: "node-circle" }));

    const label = svgElement("text", { x, y: y - 2, class: "node-label" });
    label.textContent = node.id;
    const sub = svgElement("text", { x, y: y + 14, class: "node-sub" });
    sub.textContent = node.state === "ISOLATED" ? seconds(node.quarantine_left_ms) : `${node.attacks} hits`;
    group.append(label, sub);

    const select = () => { selectedId = node.id === selectedId ? null : node.id; render(); };
    group.addEventListener("click", select);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
    });
    ui.ring.appendChild(group);
  });
}

function renderPanels() {
  ui.clock.textContent = seconds(state.now_ms);
  ui.exposed.textContent = state.exposed_id || "-";
  ui.nextRotation.textContent = state.next_rotation_in_ms == null ? "-" : seconds(state.next_rotation_in_ms);
  ui.selected.textContent = selectedId || "none";
  ui.selectionButtons.forEach((button) => { button.disabled = !selectedId; });
  ui.history.replaceChildren(...state.history.map((id) => {
    const item = document.createElement("li");
    item.textContent = id;
    return item;
  }));
}

function render() {
  if (!state) return;
  if (selectedId && !state.honeypots.some((node) => node.id === selectedId)) selectedId = null;
  renderRing();
  renderPanels();
}

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
bind("btn-reset", () => { selectedId = null; send("/api/reset"); });

request("/api/state");
