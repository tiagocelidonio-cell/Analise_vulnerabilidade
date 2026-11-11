// Identidade visual — ponto unico de configuracao da marca.
// Ajuste aqui para refletir a identidade da Lozinsky (cores/fonte exatas).
// O logo fica em frontend/public/logo.svg — troque o arquivo pelo seu.
export const branding = {
  appName: "Lozinsky VulnScope",
  logo: "/logo.svg",

  // Paleta (placeholder profissional escuro — troque pelos hex da marca).
  colors: {
    bg: "#0a0f1a",
    panel: "#0f1626",
    card: "#141d30",
    line: "#243049",
    text: "#e8edf5",
    muted: "#9aa7bd",
    accent: "#1f6feb",   // COR PRIMARIA — ajustar para a cor da Lozinsky
    accent2: "#00b3a4",  // cor secundaria
  },

  // Fonte (carregada no index.html). Troque pela fonte do site se for outra.
  font: "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
};

// Aplica as cores da marca como variaveis CSS no :root.
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
  document.title = branding.appName;
}
