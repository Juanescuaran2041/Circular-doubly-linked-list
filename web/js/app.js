"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const CENTER = 300;
const RING_RADIUS = 220;
const AUTO_TICK_MS = 1000;
const SPEED_STORAGE_KEY = "mirage-speed";
const SPEEDS = [1, 5, 10, 30];
const FEED_LIMIT = 40;
const MAX_PIPS = 6;
const REQUEST_TIMEOUT_MS = 12000;
const SESSION_STORAGE_KEY = "mirage-session";
const LOADING_POLL_MS = 1500;

const ui = {
  ring: document.getElementById("ring"),
  clock: document.getElementById("clock"),
  error: document.getElementById("error"),
  history: document.getElementById("history"),
  auto: document.getElementById("btn-auto"),
  theme: document.getElementById("btn-theme"),
  selectedEmpty: document.getElementById("selected-empty"),
  selectedDetail: document.getElementById("selected-detail"),
  selectedName: document.getElementById("selected-name"),
  selectedMeta: document.getElementById("selected-meta"),
  selectedMeter: document.getElementById("selected-meter"),
  feed: document.getElementById("feed"),
  feedEmpty: document.getElementById("feed-empty"),
  statAttacks: document.getElementById("stat-attacks"),
  statMissed: document.getElementById("stat-missed"),
  statRotations: document.getElementById("stat-rotations"),
  statIsolated: document.getElementById("stat-isolated"),
  statServers: document.getElementById("stat-servers"),
  threatsButton: document.getElementById("btn-threats"),
  threatSource: document.getElementById("threat-source"),
  selectionButtons: ["btn-attack", "btn-isolate", "btn-remove"].map((id) => document.getElementById(id)),
};

let state = null;
let selectedId = null;
let lastExposedId = null;
let activityResetPending = false;
let currentError = null;
let loadingPoll = null;
let serverSession = null;
let queue = Promise.resolve();
let autoRunning = false;
let speed = 5;

const session = { attacks: 0, rotations: 0, feed: [], pendingHits: [], pendingMisses: [], lastEventId: 0 };

/* ---------- API ---------- */

// Reads the simulation the browser kept from a previous visit, if any.
function loadStoredSession() {
  try {
    const stored = localStorage.getItem(SESSION_STORAGE_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch (error) {
    return null;
  }
}

// Keeps the simulation in the browser so a reload continues where it stopped.
function storeSession(value) {
  try {
    if (value) localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(value));
    else localStorage.removeItem(SESSION_STORAGE_KEY);
  } catch (error) {
    // Storage can be blocked; the simulation still works until the page is closed.
  }
}

// Runs requests one after another: when the server keeps no state, each one must start from the previous result.
function request(path, body) {
  const result = queue.then(() => execute(path, body));
  queue = result.catch(() => {});
  return result;
}

// Calls the API (GET when there is no body, POST otherwise) and re-renders with the new snapshot.
async function execute(path, body) {
  const payload = body !== undefined && serverSession ? { ...body, session: serverSession } : body;
  const options = payload === undefined
    ? {}
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(path, { ...options, signal: controller.signal });
    const data = await response.json();
    if (!response.ok) {
      showError({ code: data.code, params: data.params, fallback: data.error, status: response.status });
      return;
    }
    showError(null);
    if (data.session) {
      serverSession = data.session;
      storeSession(serverSession);
    }
    delete data.session;
    trackChanges(state, data);
    state = data;
    render();
  } catch (error) {
    showError({ code: error.name === "AbortError" ? "timeout" : "network" });
  } finally {
    clearTimeout(timer);
  }
}

const send = (path, body = {}) => request(path, body);

// Remembers the error (not its text) so it can be translated again when the language changes.
function showError(error) {
  currentError = error;
  renderError();
}

function renderError() {
  ui.error.hidden = !currentError;
  if (!currentError) return;
  const { code, params, fallback, status } = currentError;
  const key = `error.${code}`;
  const known = TRANSLATIONS[language][key] !== undefined;
  ui.error.textContent = known
    ? t(key, params || {})
    : fallback || t("error.request", { status: status ?? "?" });
}

/* ---------- Activity derived from consecutive snapshots ---------- */

// Feed entries keep a translation key and its values, so they follow the language.
function logEvent(time, kind, key, params = {}, detail = null) {
  session.feed.unshift({ time, kind, key, params, detail });
  session.feed.length = Math.min(session.feed.length, FEED_LIMIT);
}

function resetActivity() {
  session.attacks = 0;
  session.rotations = 0;
  session.feed = [];
  session.pendingHits = [];
  session.pendingMisses = [];
  lastExposedId = null;
}

function latestEventId(snapshot) {
  const events = (snapshot.threats && snapshot.threats.events) || [];
  return events.reduce((latest, event) => Math.max(latest, event.id), 0);
}

// Logs the replayed attackers that arrived since the last snapshot; returns the servers they struck.
function trackThreats(current) {
  const events = (current.threats && current.threats.events) || [];
  const fresh = events.filter((event) => event.id > session.lastEventId);
  session.lastEventId = Math.max(session.lastEventId, latestEventId(current));

  const struck = new Set();
  for (const event of fresh) {
    const detail = { key: "feed.reports", params: { n: event.reports } };
    if (event.outcome === "landed") {
      struck.add(event.target);
      session.attacks += 1;
      logEvent(event.time_ms, "attack", "feed.struck", { ip: event.ip, target: event.target }, detail);
    } else {
      session.pendingMisses.push(event.target);
      logEvent(event.time_ms, "miss", "feed.missed", { ip: event.ip, target: event.target }, detail);
    }
  }
  return struck;
}

// Compares two snapshots and records what changed: attacks, rotations, quarantines and membership.
function trackChanges(previous, current) {
  const timeWentBack = previous && current.now_ms < previous.now_ms;
  if (activityResetPending || timeWentBack || !previous) {
    activityResetPending = false;
    resetActivity();
    session.lastEventId = latestEventId(current);
    return;
  }

  const time = current.now_ms;
  const covered = trackThreats(current);
  const before = new Map(previous.honeypots.map((node) => [node.id, node]));
  const after = new Map(current.honeypots.map((node) => [node.id, node]));

  for (const [id, node] of after) {
    const old = before.get(id);
    if (!old) {
      logEvent(time, "ring", "feed.joined", { id });
      continue;
    }
    if (node.attacks > old.attacks) {
      session.pendingHits.push(id);
      if (!covered.has(id)) {
        session.attacks += node.attacks - old.attacks;
        logEvent(time, "attack", "feed.attacked", {
          id, attacks: node.attacks, threshold: current.config.attack_threshold,
        });
      }
    }
    if (node.state === "ISOLATED" && old.state !== "ISOLATED") {
      logEvent(time, "isolate", "feed.quarantined", { id });
    }
    if (old.state === "ISOLATED" && node.state !== "ISOLATED") {
      logEvent(time, "release", "feed.released", { id });
    }
  }
  for (const id of before.keys()) {
    if (!after.has(id)) logEvent(time, "ring", "feed.removed", { id });
  }

  const moves = appendedCount(previous.history, current.history);
  if (current.exposed_id && moves > 0) {
    session.rotations += moves;
    if (moves > 1) {
      logEvent(time, "rotate", "feed.movedMany", { n: moves, to: current.exposed_id });
    } else if (previous.exposed_id) {
      logEvent(time, "rotate", "feed.moved", { from: previous.exposed_id, to: current.exposed_id });
    } else {
      logEvent(time, "rotate", "feed.movedFromNone", { to: current.exposed_id });
    }
  }
}

// Counts how many exposures were appended to the history, even when several happen between two snapshots.
function appendedCount(before, after) {
  for (let skipped = 0; skipped <= before.length; skipped += 1) {
    const overlap = before.slice(skipped);
    if (overlap.length <= after.length && overlap.every((id, index) => after[index] === id)) {
      return after.length - overlap.length;
    }
  }
  return after.length;
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

function addArrowMarker(defs, id) {
  const marker = svgElement("marker", {
    id, viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto",
  });
  marker.appendChild(svgElement("path", { d: "M 0 1 L 9 5 L 0 9 z", class: id }));
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
  if (node.state !== "EXPOSED") return;
  const { x, y } = pointAt(angleOf(index, total));
  ui.ring.appendChild(svgElement("polygon", { points: hexagonPoints(x, y, size), class: "ripple" }));
}

// A beam coming from outside the ring: red when it strikes a server, violet when it fizzles short of it.
function drawBeam(index, total, size, missed = false) {
  const angle = angleOf(index, total);
  const start = pointAt(angle, RING_RADIUS + 150);
  const end = pointAt(angle, RING_RADIUS + size + (missed ? 40 : 6));
  ui.ring.appendChild(svgElement("path", {
    d: `M ${start.x} ${start.y} L ${end.x} ${end.y}`, class: missed ? "beam miss" : "beam", pathLength: 1,
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

  const stateLabel = t(`state.${node.state}`).toLowerCase();
  const group = svgElement("g", {
    class: classes.join(" "), tabindex: 0, role: "button",
    "aria-label": `${node.id}, ${stateLabel}${node.id === selectedId ? `, ${t("node.selected")}` : ""}`,
  });
  group.appendChild(svgElement("polygon", { points: hexagonPoints(x, y, size), class: "node-shape" }));

  const label = svgElement("text", { x, y: y - 1, class: "node-id" });
  label.textContent = node.id;
  const detail = svgElement("text", { x, y: y + 15, class: "node-sub" });
  detail.textContent = node.state === "ISOLATED"
    ? seconds(node.quarantine_left_ms)
    : t("node.hits", { n: node.attacks });
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
  title.textContent = state.exposed_id || t("center.none");
  const caption = svgElement("text", { x: CENTER, y: CENTER + 40, class: "center-line" });
  caption.textContent = state.exposed_id
    ? t("center.exposed", { time: seconds(state.next_rotation_in_ms) })
    : t("center.nothing");
  ui.ring.append(title, caption);
}

function renderRing() {
  const nodes = state.honeypots;
  const size = nodeSize(nodes.length);
  const struck = new Set(session.pendingHits);
  const missed = new Set(session.pendingMisses);
  ui.ring.replaceChildren();

  const defs = svgElement("defs");
  addArrowMarker(defs, "head-next");
  addArrowMarker(defs, "head-prev");
  ui.ring.appendChild(defs);
  drawOrbits();

  if (nodes.length === 0) {
    const empty = svgElement("text", { x: CENTER, y: CENTER, class: "center-line" });
    empty.textContent = t("ring.empty");
    ui.ring.appendChild(empty);
    return;
  }

  drawLinks(nodes.length, size);
  nodes.forEach((node, index) => drawRipple(node, index, nodes.length, size));
  drawTrail(nodes);
  nodes.forEach((node, index) => {
    if (struck.has(node.id)) drawBeam(index, nodes.length, size);
    if (missed.has(node.id)) drawBeam(index, nodes.length, size, true);
    drawNode(node, index, nodes.length, size, struck.has(node.id));
  });
  drawCenter();
  session.pendingHits = [];
  session.pendingMisses = [];
}

/* ---------- Side panels ---------- */

// Describes where the attackers come from, in the current language.
function sourceText(threats) {
  return t(`source.${threats.source_kind}`, { n: threats.source_count });
}

// While the server loads the attacker list, ask again shortly so the interface leaves the loading state.
function scheduleLoadingRefresh() {
  const loading = state && state.threats && state.threats.enabled && state.threats.source_kind === "loading";
  if (!loading || loadingPoll !== null) return;
  loadingPoll = setTimeout(() => {
    loadingPoll = null;
    request("/api/state");
  }, LOADING_POLL_MS);
}

function renderStats() {
  const threats = state.threats || { enabled: false, missed: 0, source_kind: "pending", source_count: 0 };
  ui.statAttacks.textContent = session.attacks.toLocaleString(language);
  ui.statMissed.textContent = threats.missed.toLocaleString(language);
  ui.statRotations.textContent = session.rotations.toLocaleString(language);
  ui.statIsolated.textContent = state.honeypots.filter((node) => node.state === "ISOLATED").length;
  ui.statServers.textContent = state.honeypots.length;
  ui.threatsButton.setAttribute("aria-pressed", String(threats.enabled));
  ui.threatSource.textContent = threats.enabled
    ? t("threats.active", { source: sourceText(threats) })
    : t("threats.hint");
}

function renderSelected() {
  const node = state.honeypots.find((item) => item.id === selectedId);
  ui.selectedEmpty.hidden = Boolean(node);
  ui.selectedDetail.hidden = !node;
  ui.selectionButtons.forEach((button) => { button.disabled = !node; });
  if (!node) return;

  ui.selectedName.textContent = node.id;
  if (node.state === "ISOLATED") {
    ui.selectedMeta.textContent = t("selected.isolated", { time: seconds(node.quarantine_left_ms) });
    ui.selectedMeter.style.width = `${(node.quarantine_left_ms / state.config.quarantine_ms) * 100}%`;
    ui.selectedMeter.style.background = "var(--amber)";
  } else {
    ui.selectedMeta.textContent = t("selected.status", {
      state: t(`state.${node.state}`), attacks: node.attacks, threshold: state.config.attack_threshold,
    });
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
    text.textContent = t(entry.key, entry.params);
    if (entry.detail) {
      const detail = document.createElement("span");
      detail.className = "detail";
      detail.textContent = t(entry.detail.key, entry.detail.params);
      text.appendChild(detail);
    }
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
  scheduleLoadingRefresh();
}

/* ---------- Controls ---------- */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The button shows what a click will do: start the simulation or pause it.
function syncAutoButton() {
  ui.auto.textContent = t(autoRunning ? "auto.pause" : "auto.button");
  ui.auto.setAttribute("aria-pressed", String(autoRunning));
}

// Highlights the chosen speed.
function syncSpeedButtons() {
  document.querySelectorAll("[data-speed]").forEach((button) => {
    button.setAttribute("aria-pressed", String(Number(button.dataset.speed) === speed));
  });
}

function setSpeed(next) {
  if (!SPEEDS.includes(next)) return;
  speed = next;
  try {
    localStorage.setItem(SPEED_STORAGE_KEY, String(next));
  } catch (error) {
    // Storage can be blocked; the speed still applies for this visit.
  }
  syncSpeedButtons();
}

function loadSpeed() {
  try {
    const saved = Number(localStorage.getItem(SPEED_STORAGE_KEY));
    if (SPEEDS.includes(saved)) speed = saved;
  } catch (error) {
    // Storage can be blocked; keep the default speed.
  }
}

function stopAuto() {
  autoRunning = false;
  syncAutoButton();
}

// Advances the simulation about once per real second. The jump follows the real time that passed,
// so a slow server does not slow the simulation down, and it stops if the server fails.
async function autoLoop() {
  let last = performance.now();
  while (autoRunning) {
    await sleep(AUTO_TICK_MS);
    if (!autoRunning) break;
    const now = performance.now();
    const realSeconds = Math.max(1, Math.round((now - last) / 1000));
    last = now;
    await send("/api/time", { ms: realSeconds * speed * 1000 });
    if (currentError) stopAuto();
  }
}

function toggleAuto() {
  if (autoRunning) {
    stopAuto();
    return;
  }
  autoRunning = true;
  syncAutoButton();
  autoLoop();
}

/* ---------- Theme and language ---------- */

// The icon button describes the action it will perform, not the current theme.
function syncThemeButton() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const label = t(isLight ? "theme.toDark" : "theme.toLight");
  ui.theme.setAttribute("aria-label", label);
  ui.theme.title = label;
}

function toggleTheme() {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("mirage-theme", next);
  } catch (error) {
    // Storage can be blocked; the theme still applies for this visit.
  }
  syncThemeButton();
}

// Applies a language to the static texts and to everything drawn from the state.
function changeLanguage(next) {
  setLanguage(next);
  syncThemeButton();
  syncAutoButton();
  renderError();
  render();
}

function bind(id, handler) {
  document.getElementById(id).addEventListener("click", handler);
}

bind("btn-rotate", () => send("/api/rotate", { direction: 1 }));
bind("btn-back", () => send("/api/rotate", { direction: -1 }));
bind("btn-time-10", () => send("/api/time", { ms: 10000 }));
bind("btn-time-30", () => send("/api/time", { ms: 30000 }));
bind("btn-auto", toggleAuto);
bind("btn-theme", toggleTheme);
bind("btn-threats", async () => {
  ui.threatsButton.disabled = true;
  try {
    await send("/api/threats", { enabled: !(state && state.threats && state.threats.enabled) });
  } finally {
    ui.threatsButton.disabled = false;
  }
});
bind("btn-attack", () => selectedId && send("/api/attack", { id: selectedId }));
bind("btn-isolate", () => selectedId && send("/api/isolate", { id: selectedId }));
bind("btn-remove", () => selectedId && send("/api/remove", { id: selectedId }));
bind("btn-add", () => send("/api/add"));
bind("btn-reset", () => {
  selectedId = null;
  activityResetPending = true;
  send("/api/reset");
});
document.querySelectorAll("[data-speed]").forEach((button) => {
  button.addEventListener("click", () => setSpeed(Number(button.dataset.speed)));
});
document.querySelectorAll("[data-lang]").forEach((button) => {
  button.addEventListener("click", () => changeLanguage(button.dataset.lang));
});

applyTranslations();
// Starts from the saved simulation when there is one; a saved state that no longer validates is dropped.
async function start() {
  serverSession = loadStoredSession();
  if (serverSession) {
    await request("/api/sync", {});
    if (currentError && currentError.code === "invalid_session") {
      serverSession = null;
      storeSession(null);
      showError(null);
    }
  }
  if (!state) await request("/api/state");
}

loadSpeed();
syncSpeedButtons();
syncAutoButton();
syncThemeButton();
start();
