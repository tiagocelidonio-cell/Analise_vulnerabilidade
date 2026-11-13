// Cliente da API VulnScope.
// Base padrao: "/api" (mesma origem do painel). O servidor do painel (Vite)
// repassa /api/* para a API internamente, entao o navegador so usa a porta
// 5173 — nao precisa alcancar a 8000. Pode-se forcar outro endereco com
// VITE_API_URL (ex: atras de um dominio/HTTPS proprio).
const BASE = import.meta.env.VITE_API_URL || "/api";
const TOKEN_KEY = "vulnscope_token";

// Monta a query string das opcoes do relatorio (?min_sev=...&evidence=false...).
function _reportQs(opt) {
  if (!opt) return "";
  const p = [];
  if (opt.min_sev) p.push(`min_sev=${opt.min_sev}`);
  for (const k of ["methodology", "matrix", "targets", "evidence"]) {
    if (opt[k] === false) p.push(`${k}=false`);
  }
  return p.length ? "&" + p.join("&") : "";
}

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}
export function setToken(t) {
  try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); } catch {}
}

async function req(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(BASE + path, { ...opts, headers });
  if (res.status === 401) {
    setToken(null);
    throw new Error("Sessão expirada. Faça login novamente.");
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Erro ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}

export const api = {
  base: BASE,
  // auth
  login: async (email, password) => {
    const r = await req("/auth/login", {
      method: "POST", body: JSON.stringify({ email, password }),
    });
    setToken(r.access_token);
    return r;
  },
  me: () => req("/auth/me"),
  updateMe: (body) => req("/auth/me", { method: "PATCH", body: JSON.stringify(body) }),
  getConfig: () => req("/config"),
  updateConfig: (body) => req("/config", { method: "PUT", body: JSON.stringify(body) }),
  logout: () => setToken(null),
  listUsers: () => req("/auth/users"),
  createUser: (body) => req("/auth/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id, body) => req(`/auth/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteUser: (id) => req(`/auth/users/${id}`, { method: "DELETE" }),
  overview: () => req("/overview"),
  cveStatus: () => req("/cve/status"),
  cveUpdate: (full = false) => req(`/cve/update?full=${full}`, { method: "POST" }),
  cveSchedule: () => req("/cve/schedule"),
  cveScheduleSet: (body) => req("/cve/schedule", { method: "PUT", body: JSON.stringify(body) }),
  overviewReportHtmlUrl: () => `${BASE}/overview/report.html?token=${getToken() || ""}`,
  overviewReportPdfUrl: () => `${BASE}/overview/report.pdf?token=${getToken() || ""}`,
  // engagements
  listEngagements: () => req("/engagements"),
  createEngagement: (body) =>
    req("/engagements", { method: "POST", body: JSON.stringify(body) }),
  getEngagement: (id) => req(`/engagements/${id}`),
  updateEngagement: (id, body) =>
    req(`/engagements/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteEngagement: (id) => req(`/engagements/${id}`, { method: "DELETE" }),
  listScans: (id) => req(`/engagements/${id}/scans`),
  createScan: (id, body) =>
    req(`/engagements/${id}/scans`, { method: "POST", body: JSON.stringify(body) }),
  getScan: (sid) => req(`/scans/${sid}`),
  cancelScan: (sid) => req(`/scans/${sid}/cancel`, { method: "POST" }),
  pauseScan: (sid) => req(`/scans/${sid}/pause`, { method: "POST" }),
  resumeScan: (sid) => req(`/scans/${sid}/resume`, { method: "POST" }),
  deleteScan: (sid, delFindings = false) => req(`/scans/${sid}?delete_findings=${delFindings}`, { method: "DELETE" }),
  deleteFindings: (id, ids) => req(`/engagements/${id}/findings/delete`, { method: "POST", body: JSON.stringify({ ids }) }),
  listFindings: (id) => req(`/engagements/${id}/findings`),
  risk: (id) => req(`/engagements/${id}/risk`),
  assets: (id) => req(`/engagements/${id}/assets`),
  validate: (id, opts = {}) =>
    req(`/engagements/${id}/validate`, {
      method: "POST",
      body: JSON.stringify({
        intrusive: !!opts.intrusive,
        targets: opts.targets || [],
      }),
    }),
  retest: (id) => req(`/engagements/${id}/retest`, { method: "POST" }),
  postexploit: (id) => req(`/engagements/${id}/postexploit`),
  // relatorios: token no query para abrir em nova aba + opcoes de conteudo
  reportHtmlUrl: (id, opt) => `${BASE}/engagements/${id}/report.html?token=${getToken() || ""}${_reportQs(opt)}`,
  reportPdfUrl: (id, opt) => `${BASE}/engagements/${id}/report.pdf?token=${getToken() || ""}${_reportQs(opt)}`,
};
