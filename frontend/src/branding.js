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

// Skins predefinidas — cada uma com o conjunto COMPLETO de cores, garantindo
// contraste texto/fundo em TODAS as telas (texto claro em fundo escuro e
// vice-versa). O usuario pode escolher uma e depois ajustar cores individuais.
export const SKINS = {
  dark: {
    name: "Escuro (padrão)",
    colors: { bg: "#000000", panel: "#0b0b0c", card: "#121214", line: "#26262b",
      text: "#f2f2f2", muted: "#9aa3ad", accent: "#0fdb2b", accent2: "#1c476b" },
  },
  light: {
    name: "Claro",
    colors: { bg: "#f3f4f6", panel: "#ffffff", card: "#ffffff", line: "#d7dbe2",
      text: "#14181f", muted: "#596270", accent: "#0a7d2b", accent2: "#1c476b" },
  },
  slate: {
    name: "Azul-ardósia",
    colors: { bg: "#0b1220", panel: "#0f1a2e", card: "#15223c", line: "#273449",
      text: "#e8edf6", muted: "#94a3b8", accent: "#38bdf8", accent2: "#6366f1" },
  },
  midnight: {
    name: "Meia-noite (roxo)",
    colors: { bg: "#13111c", panel: "#1b1830", card: "#221d3a", line: "#352d53",
      text: "#ece9f6", muted: "#a79fc4", accent: "#a855f7", accent2: "#22d3ee" },
  },
  contrast: {
    name: "Alto contraste",
    colors: { bg: "#000000", panel: "#000000", card: "#0a0a0a", line: "#ffffff",
      text: "#ffffff", muted: "#d4d4d4", accent: "#00ff66", accent2: "#ffd400" },
  },
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
