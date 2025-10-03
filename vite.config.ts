import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
export default defineConfig(({ command }) => ({
  base: command === 'build' ? './' : '/',
  build: {
    outDir: 'web',
    emptyOutDir: true,
  },
  plugins: [
    react(),
    VitePWA({
      injectRegister: null,
      registerType: 'autoUpdate',
      workbox: {
        globDirectory: 'web',
        globPatterns: ['**/*.{js,css,html}'],
        globIgnores: ['sw.js', 'workbox-*.js'],
      },
    }),
  ],
}));
