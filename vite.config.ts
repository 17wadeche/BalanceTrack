import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
export default defineConfig({
  build: {
    outDir: 'web',       // <— was "dist"
    emptyOutDir: true
  },
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      workbox: {
        globDirectory: 'web',
        globPatterns: ['**/*.{js,css,html}'],
        globIgnores: ['sw.js', 'workbox-*.js']
      }
    })
  ]
});
