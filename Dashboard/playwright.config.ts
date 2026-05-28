import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  retries: 0,
  use: {
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
    viewport: { width: 1280, height: 720 },
  },
  webServer: {
    command: 'python -m http.server 4173',
    cwd: './dist',
    port: 4173,
    timeout: 10000,
    reuseExistingServer: false,
  },
});
