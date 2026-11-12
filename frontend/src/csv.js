// Export CSV simples (sem libs). Gera e baixa um .csv no navegador.
function esc(v) {
  if (v === null || v === undefined) return "";
  const s = Array.isArray(v) ? v.join("; ") : String(v);
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function downloadCsv(filename, rows, columns) {
  // columns: [{key, label}]
  const header = columns.map((c) => esc(c.label)).join(",");
  const body = rows.map((r) => columns.map((c) => esc(
    typeof c.get === "function" ? c.get(r) : r[c.key])).join(",")).join("\n");
  const csv = "﻿" + header + "\n" + body; // BOM p/ acentos no Excel
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
