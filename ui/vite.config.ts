import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/_/mpc/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: { manualChunks: undefined },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/v1/mpc': 'http://localhost:8081',
    },
  },
})
