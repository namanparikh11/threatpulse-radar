import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // `base: './'` emits relative asset URLs in `dist/index.html` so the
  // built bundle works whether Hostinger serves it at a subdomain
  // root (e.g. `https://radar.example.com/`) or under a subpath
  // (e.g. `https://example.com/threatpulse/`). Without this, the
  // default `'/'` breaks any subpath deployment.
  base: './',
  server: {
    port: 5173,
  },
  build: {
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom'],
          charts: ['recharts'],
          icons: ['lucide-react'],
        },
      },
    },
  },
});
