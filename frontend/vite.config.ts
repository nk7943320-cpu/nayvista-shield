import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://127.0.0.1:5000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res: any) => {
            if (res && !res.headersSent) {
              res.writeHead(503, {
                'Content-Type': 'application/json; charset=utf-8',
              });
              res.end(
                JSON.stringify({
                  success: false,
                  error: 'Assessment API unavailable. The NayVista Shield backend server is not reachable.',
                  code: 'API_UNAVAILABLE',
                })
              );
            }
          });
        },
      },
    },
  },
});
