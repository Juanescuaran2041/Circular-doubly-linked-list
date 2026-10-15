"use strict";

const LANGUAGE_KEY = "mirage-language";
const SUPPORTED_LANGUAGES = ["en", "es"];

const TRANSLATIONS = {
  en: {
    "brand.tagline": "A moving target of honeypots",
    "clock.caption": "simulated time",
    "auto.button": "Run automatically",
    "theme.toLight": "Switch to light mode",
    "theme.toDark": "Switch to dark mode",
    "lang.group": "Language",

    "stat.attacks": "Attacks absorbed",
    "stat.missed": "Missed by rotation",
    "stat.rotations": "Rotations",
    "stat.isolated": "In quarantine",
    "stat.servers": "Servers in ring",

    "stage.label": "Honeypot ring",
    "ring.aria": "Circular ring of honeypots",
    "ring.empty": "The ring is empty. Add a honeypot to start.",
    "legend.exposed": "Exposed",
    "legend.waiting": "Waiting",
    "legend.isolated": "Isolated",
    "legend.next": "next",
    "legend.prev": "prev",

    "state.EXPOSED": "Exposed",
    "state.WAITING": "Waiting",
    "state.ISOLATED": "Isolated",
    "node.hits": "{n} hits",
    "node.hits_one": "{n} hit",
    "node.selected": "selected",
    "center.none": "No target",
    "center.exposed": "exposed, moves in {time}",
    "center.nothing": "nothing is exposed right now",

    "rotation.title": "Rotation",
    "rotation.back": "Step back",
    "rotation.forward": "Rotate",
    "rotation.wait10": "Wait 10 s",
    "rotation.wait30": "Wait 30 s",

    "selected.title": "Selected server",
    "selected.hint": "Select a server on the ring to attack, isolate or remove it.",
    "selected.attack": "Attack",
    "selected.isolate": "Isolate",
    "selected.remove": "Remove",
    "selected.isolated": "Isolated, back in {time}",
    "selected.status": "{state}, {attacks} of {threshold} attacks",

    "ring.title": "Ring",
    "ring.add": "Add honeypot",
    "ring.reset": "Reset simulation",

    "threats.title": "Real attackers",
    "threats.hint": "Replays the top attacking IPs reported to SANS ISC DShield while time runs.",
    "threats.button": "Replay real attackers",
    "threats.active": "Source: {source}. Attacks arrive while time runs.",
    "source.live": "SANS ISC DShield, top {n} attacking IPs",
    "source.offline": "Offline sample (SANS ISC could not be reached)",
    "source.pending": "SANS ISC DShield (not loaded yet)",
    "source.loading": "SANS ISC DShield (loading the list, attacks start when it is ready)",

    "activity.title": "Activity",
    "activity.empty": "Nothing has happened yet. Attack a server or rotate the ring.",
    "history.title": "Exposure history",

    "feed.joined": "{id} joined the ring",
    "feed.removed": "{id} was removed",
    "feed.attacked": "{id} was attacked ({attacks} of {threshold})",
    "feed.quarantined": "{id} moved to quarantine",
    "feed.released": "{id} left quarantine",
    "feed.moved": "Exposure moved from {from} to {to}",
    "feed.movedFromNone": "Exposure moved to {to}",
    "feed.movedMany": "Exposure moved {n} times and now sits on {to}",
    "feed.struck": "{ip} struck {target}",
    "feed.missed": "{ip} aimed at {target}, which had already rotated away",
    "feed.reports": "Reported {n} times by SANS ISC sensors",
    "feed.reports_one": "Reported {n} time by SANS ISC sensors",

    "error.network": "Cannot reach the server. Is `python main.py` running?",
    "error.request": "Request failed ({status})",
    "error.duplicate_honeypot": "A honeypot with id {id} already exists",
    "error.unknown_honeypot": "Unknown honeypot: {id}",
    "error.invalid_direction": "Direction must be 1 (forward) or -1 (backward)",
    "error.isolated_honeypot": "{id} is isolated and cannot be attacked",
    "error.negative_time": "Time cannot go backward",
    "error.time_too_large": "A single time step cannot exceed {max} ms",
    "error.field_invalid": "'{field}' is required and must be of type {type}",
    "error.invalid_json": "The request is not valid JSON",
    "error.body_not_object": "The JSON body must be an object",
    "error.body_too_large": "The request body is too large",
    "error.unknown_route": "Unknown route",
    "error.not_found": "Not found",
    "error.internal_error": "The server hit an unexpected error. Check the terminal where it is running",
    "error.timeout": "The server took too long to answer",
  },

  es: {
    "brand.tagline": "Un objetivo móvil de honeypots",
    "clock.caption": "tiempo simulado",
    "auto.button": "Ejecutar automáticamente",
    "theme.toLight": "Cambiar a modo claro",
    "theme.toDark": "Cambiar a modo oscuro",
    "lang.group": "Idioma",

    "stat.attacks": "Ataques absorbidos",
    "stat.missed": "Fallidos por rotación",
    "stat.rotations": "Rotaciones",
    "stat.isolated": "En cuarentena",
    "stat.servers": "Servidores en el anillo",

    "stage.label": "Anillo de honeypots",
    "ring.aria": "Anillo circular de honeypots",
    "ring.empty": "El anillo está vacío. Agrega un honeypot para empezar.",
    "legend.exposed": "Expuesto",
    "legend.waiting": "En espera",
    "legend.isolated": "Aislado",
    "legend.next": "siguiente",
    "legend.prev": "anterior",

    "state.EXPOSED": "Expuesto",
    "state.WAITING": "En espera",
    "state.ISOLATED": "Aislado",
    "node.hits": "{n} impactos",
    "node.hits_one": "{n} impacto",
    "node.selected": "seleccionado",
    "center.none": "Sin objetivo",
    "center.exposed": "expuesto, cambia en {time}",
    "center.nothing": "nada está expuesto ahora",

    "rotation.title": "Rotación",
    "rotation.back": "Retroceder",
    "rotation.forward": "Rotar",
    "rotation.wait10": "Esperar 10 s",
    "rotation.wait30": "Esperar 30 s",

    "selected.title": "Servidor seleccionado",
    "selected.hint": "Selecciona un servidor del anillo para atacarlo, aislarlo o retirarlo.",
    "selected.attack": "Atacar",
    "selected.isolate": "Aislar",
    "selected.remove": "Retirar",
    "selected.isolated": "Aislado, vuelve en {time}",
    "selected.status": "{state}, {attacks} de {threshold} ataques",

    "ring.title": "Anillo",
    "ring.add": "Agregar honeypot",
    "ring.reset": "Reiniciar simulación",

    "threats.title": "Atacantes reales",
    "threats.hint": "Reproduce las IP que más atacan según SANS ISC DShield mientras corre el tiempo.",
    "threats.button": "Reproducir atacantes reales",
    "threats.active": "Fuente: {source}. Los ataques llegan mientras corre el tiempo.",
    "source.live": "SANS ISC DShield, las {n} IP que más atacan",
    "source.offline": "Muestra sin conexión (no se pudo contactar a SANS ISC)",
    "source.pending": "SANS ISC DShield (aún sin cargar)",
    "source.loading": "SANS ISC DShield (cargando la lista, los ataques empiezan cuando esté lista)",

    "activity.title": "Actividad",
    "activity.empty": "Aún no ha pasado nada. Ataca un servidor o rota el anillo.",
    "history.title": "Historial de exposición",

    "feed.joined": "{id} entró al anillo",
    "feed.removed": "{id} fue retirado",
    "feed.attacked": "{id} fue atacado ({attacks} de {threshold})",
    "feed.quarantined": "{id} pasó a cuarentena",
    "feed.released": "{id} salió de cuarentena",
    "feed.moved": "La exposición pasó de {from} a {to}",
    "feed.movedFromNone": "La exposición pasó a {to}",
    "feed.movedMany": "La exposición cambió {n} veces y ahora está en {to}",
    "feed.struck": "{ip} atacó a {target}",
    "feed.missed": "{ip} apuntó a {target}, que ya había rotado",
    "feed.reports": "Reportada {n} veces por sensores de SANS ISC",
    "feed.reports_one": "Reportada {n} vez por sensores de SANS ISC",

    "error.network": "No se puede contactar al servidor. ¿Está corriendo `python main.py`?",
    "error.request": "La solicitud falló ({status})",
    "error.duplicate_honeypot": "Ya existe un honeypot con el id {id}",
    "error.unknown_honeypot": "Honeypot desconocido: {id}",
    "error.invalid_direction": "La dirección debe ser 1 (adelante) o -1 (atrás)",
    "error.isolated_honeypot": "{id} está aislado y no puede ser atacado",
    "error.negative_time": "El tiempo no puede retroceder",
    "error.time_too_large": "Un solo avance de tiempo no puede superar {max} ms",
    "error.field_invalid": "'{field}' es obligatorio y debe ser de tipo {type}",
    "error.invalid_json": "La solicitud no es un JSON válido",
    "error.body_not_object": "El cuerpo JSON debe ser un objeto",
    "error.body_too_large": "El cuerpo de la solicitud es demasiado grande",
    "error.unknown_route": "Ruta desconocida",
    "error.not_found": "No encontrado",
    "error.internal_error": "El servidor tuvo un error inesperado. Revisa la terminal donde está corriendo",
    "error.timeout": "El servidor tardó demasiado en responder",
  },
};

let language = detectLanguage();

// Picks the saved language, then the browser language, then English.
function detectLanguage() {
  try {
    const saved = localStorage.getItem(LANGUAGE_KEY);
    if (SUPPORTED_LANGUAGES.includes(saved)) return saved;
  } catch (error) {
    // Storage can be blocked; fall through to the browser language.
  }
  return (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en";
}

// Translates a key, picking the singular form when `n` is 1 and filling {placeholders}.
function t(key, params = {}) {
  const table = TRANSLATIONS[language];
  const singular = params.n === 1 ? table[`${key}_one`] : undefined;
  const template = singular ?? table[key] ?? TRANSLATIONS.en[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (placeholder, name) => {
    if (!(name in params)) return placeholder;
    const value = params[name];
    return typeof value === "number" ? value.toLocaleString(language === "es" ? "es-ES" : "en-US") : String(value);
  });
}

// Translates every element of the page marked with a data-i18n attribute.
function applyTranslations() {
  document.documentElement.lang = language;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
  });
  document.querySelectorAll("[data-lang]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.lang === language));
  });
}

// Changes the language, remembers it and refreshes the static texts.
function setLanguage(next) {
  if (!SUPPORTED_LANGUAGES.includes(next)) return;
  language = next;
  try {
    localStorage.setItem(LANGUAGE_KEY, next);
  } catch (error) {
    // Storage can be blocked; the language still applies for this visit.
  }
  applyTranslations();
}
