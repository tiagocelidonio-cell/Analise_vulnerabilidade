// Identidade visual — alinhada ao site lozinskyconsultoria.com.br
// Verde da marca #0fdb2b, fundo preto, títulos em IBM Plex Mono.
export const branding = {
  appName: "Lozinsky VulnScope",
  logo: "/logo.svg",

  colors: {
    bg: "#000000",
    panel: "#0b0b0c",
    card: "#121214",
    line: "#26262b",
    text: "#f2f2f2",
    muted: "#9aa3ad",
    accent: "#0fdb2b",    // verde Lozinsky
    accent2: "#1c476b",   // azul secundário
  },

  // Fontes do site (carregadas no index.html).
  font: "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
  headingFont: "'IBM Plex Mono', ui-monospace, 'Cascadia Code', monospace",
};

// Aplica a marca como variáveis CSS no :root.
export function applyBranding() {
  const r = document.documentElement;
  const c = branding.colors;
  r.style.setProperty("--bg", c.bg);
  r.style.setProperty("--panel", c.panel);
  r.style.setProperty("--card", c.card);
  r.style.setProperty("--line", c.line);
  r.style.setProperty("--text", c.text);
  r.style.setProperty("--muted", c.muted);
  r.style.setProperty("--accent", c.accent);
  r.style.setProperty("--accent2", c.accent2);
  r.style.setProperty("--font", branding.font);
  r.style.setProperty("--heading-font", branding.headingFont);
  document.title = branding.appName;
}
