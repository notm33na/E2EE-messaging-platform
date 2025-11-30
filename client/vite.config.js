import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    https: false, // Frontend runs on HTTP, backend handles HTTPS
    proxy: {
      '/api': {
        target: 'https://localhost:8443',
        changeOrigin: true,
        secure: false, // Allow self-signed certificates
        rewrite: (path) => path
      }
    }
  }
});

