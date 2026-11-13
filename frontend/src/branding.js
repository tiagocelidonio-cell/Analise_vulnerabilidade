// Identidade visual — padrao Lozinsky, sobrescrito pela config da plataforma.
import { api } from "./api.js";

const DEFAULTS = {
  appName: "Lozinsky VulnScope",
  logo: "/logo.svg",
  colors: {
    bg: "#000000", panel: "#0b0b0c", card: "#121214", line: "#26262b",
    text: "#f2f2f2", muted: "#9aa3ad", accent: "#0fdb2b", accent2: "#1c476b",
  },
  font: "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
  headingFont: "'IBM Plex Mono', ui-monospace, 'Cascadia Code', monospace",
  timezone: "America/Sao_Paulo",
};

// Estado "vivo" da marca (mutavel): a tela de admin atualiza e re-aplica.
export const branding = {
  appName: DEFAULTS.appName, logo: DEFAULTS.logo,
  colors: { ...DEFAULTS.colors }, font: DEFAULTS.font,
  headingFont: DEFAULTS.headingFont, timezone: DEFAULTS.timezone,
};

const _listeners = new Set();
export function onBrandingChange(cb) { _listeners.add(cb); return () => _listeners.delete(cb); }

function apply() {
  const r = document.documentElement;
  const c = branding.colors;
  for (const k of ["bg", "panel", "card", "line", "text", "muted", "accent", "accent2"]) {
    if (c[k]) r.style.setProperty(`--${k}`, c[k]);
  }
  r.style.setProperty("--font", branding.font);
  r.style.setProperty("--heading-font", branding.headingFont);
  document.title = branding.appName;
  _listeners.forEach((cb) => { try { cb(); } catch { /* */ } });
}

export function applyBranding() { apply(); }

// Mescla uma config vinda do backend no estado e re-aplica.
export function applyConfig(cfg) {
  if (!cfg) return;
  if (cfg.platform_name) branding.appName = cfg.platform_name;
  if (cfg.logo) branding.logo = cfg.logo;
  if (cfg.colors && typeof cfg.colors === "object") {
    branding.colors = { ...DEFAULTS.colors, ...cfg.colors };
  }
  if (cfg.font) branding.font = cfg.font;
  if (cfg.heading_font) branding.headingFont = cfg.heading_font;
  if (cfg.timezone) branding.timezone = cfg.timezone;
  apply();
}

// Busca a config publica e aplica (chamado no boot).
export async function loadBranding() {
  apply(); // aplica defaults primeiro (evita flash)
  try { applyConfig(await api.getConfig()); } catch { /* usa defaults */ }
}

// ---- Datas com o fuso horario configurado ----
export function fmtDateTime(ts) {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString("pt-BR", { timeZone: branding.timezone });
  } catch { return new Date(ts).toLocaleString("pt-BR"); }
}
export function fmtDate(ts) {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleDateString("pt-BR", { timeZone: branding.timezone });
  } catch { return new Date(ts).toLocaleDateString("pt-BR"); }
}
