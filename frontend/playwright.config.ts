import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e', fullyParallel: false, workers: 1, retries: 0,
  use: { baseURL: 'http://127.0.0.1:3018', trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  webServer: { command: '../.venv/bin/python ../tests/e2e_server.py', url: 'http://127.0.0.1:3018/api/v1/health', reuseExistingServer: false },
});
