import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir:'./tests/browser', fullyParallel:false, workers:1, retries:0, timeout:30000,
  reporter:'list', use:{ baseURL:'http://127.0.0.1:18331', screenshot:'only-on-failure', trace:'off' },
  // Each device suite gets its own process; global admission budgets are real
  // security controls and must not be disabled to make a fast test suite pass.
  webServer:[18331,18332].map(port => ({ command:`python3 serve.py --port ${port}`,
    url:`http://127.0.0.1:${port}/api/status`, reuseExistingServer:false, timeout:15000 })),
  projects:[{ name:'chromium-desktop', use:{ ...devices['Desktop Chrome'], viewport:{width:1440,height:1000} } },
            { name:'chromium-mobile', use:{ ...devices['Pixel 7'], baseURL:'http://127.0.0.1:18332' } }],
});
