// Cliente da API VulnScope. Base configuravel via VITE_API_URL.
const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Erro ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}

export const api = {
  base: BASE,
  listEngagements: () => req("/engagements"),
  createEngagement: (body) =>
    req("/engagements", { method: "POST", body: JSON.stringify(body) }),
  getEngagement: (id) => req(`/engagements/${id}`),
  listScans: (id) => req(`/engagements/${id}/scans`),
  createScan: (id, body) =>
    req(`/engagements/${id}/scans`, { method: "POST", body: JSON.stringify(body) }),
  getScan: (sid) => req(`/scans/${sid}`),
  listFindings: (id) => req(`/engagements/${id}/findings`),
  reportHtmlUrl: (id) => `${BASE}/engagements/${id}/report.html`,
  reportPdfUrl: (id) => `${BASE}/engagements/${id}/report.pdf`,
};
