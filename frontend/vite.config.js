import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// O painel chama /api/* e o Vite repassa para o container da API (api:8000).
// Assim o navegador so precisa da porta 5173 — nao precisa alcancar a 8000.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": {
        target: "http://api:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
