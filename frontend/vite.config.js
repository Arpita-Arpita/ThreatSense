import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server on :5173 — must match FRONTEND_ORIGIN in backend/.env (CORS).
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
