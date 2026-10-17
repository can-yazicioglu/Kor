// Maintainer-only capture of the real local UI using public synthetic fixtures.
// Start app/serve.py on port 18341 first. No browser state or traces are saved.
import { chromium, expect } from '../app/node_modules/@playwright/test/index.mjs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const base = new URL(process.argv[2] ?? 'http://127.0.0.1:18341');
if (!['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname) ||
    !['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
  throw new Error('Capture requires a local demo URL without credentials.');
}
const output = path.join(root, '.local/repo-media');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  recordVideo: { dir: output, size: { width: 1152, height: 800 } },
  reducedMotion: 'reduce',
});
const page = await context.newPage();
const errors = [], external = [];
page.on('pageerror', error => errors.push(error.message));
page.on('request', request => {
  if (new URL(request.url()).origin !== base.origin) external.push(request.url());
});
const pause = ms => page.waitForTimeout(ms); // Deliberate reading time in the recording.
try {
  await page.goto(new URL('/company.html', base).href);
  await expect(page.locator('#fill-demo')).toBeEnabled();
  await page.screenshot({ path: path.join(root, 'docs/screenshots/desktop.png') });
  await pause(1800);
  await page.getByRole('link', { name: 'Risk monitor', exact: true }).click();
  await page.locator('#run-brute').scrollIntoViewIfNeeded();
  await pause(1000);
  await page.locator('#run-brute').click();
  await expect(page.locator('#event-total')).toHaveText('20 EVENTS');
  await page.getByRole('link', { name: 'Employee portal', exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect(page.locator('#risk-action')).toContainText('review');
  await pause(3300);
  await page.screenshot({ path: path.join(root, 'docs/screenshots/attack-review.png') });
  await page.locator('#fill-demo').click();
  await pause(500);
  await page.locator('#sign-in').click();
  await expect(page.locator('#mfa-panel')).toBeVisible();
  await expect(page.locator('#password')).toHaveValue('');
  await pause(2300);
  await page.locator('#mfa-code').pressSequentially('123456', { delay: 120 });
  await page.locator('#mfa-submit').click();
  await expect(page.locator('#workspace-panel')).toBeVisible();
  await pause(2300);
  await page.getByRole('link', { name: 'Security lab', exact: true }).click();
  await pause(1800);
  await page.locator('#check-receipt').click();
  await expect(page.locator('#proof-result')).toContainText('Altered score rejected');
  await page.locator('#open-resource').click();
  await expect(page.locator('#resource-result')).toContainText('Employee workspace authorized');
  await pause(1800);
  await page.locator('#try-restricted').click();
  await expect(page.locator('#resource-result')).toContainText('Server denied access');
  // Resource responses refresh the view; run the proof again for the still.
  await page.locator('#check-receipt').click();
  await expect(page.locator('#proof-result')).toContainText('Altered score rejected');
  await page.screenshot({ path: path.join(root, 'docs/screenshots/security-proof.png') });
  await page.locator('#security-desk').screenshot({ path: path.join(root, 'docs/screenshots/security-desk.png') });
  await pause(3300);
  await page.getByRole('link', { name: 'Evidence & privacy', exact: true }).click();
  await pause(2500);
  await page.locator('#reset-company').click();
  await expect(page.locator('#event-total')).toHaveText('0 EVENTS');
  await expect(page.locator('#access-role')).toHaveText('anonymous');
  await expect(page.locator('#receipt-status')).toHaveText('Waiting for a decision');
  await page.getByRole('link', { name: 'Employee portal', exact: true }).click();
  await pause(1600);
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie])).toEqual([0, 0, '']);
  const mobileContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  try {
    const mobile = await mobileContext.newPage();
    await mobile.goto(new URL('/company.html', base).href);
    await expect(mobile.locator('#fill-demo')).toBeEnabled();
    await mobile.locator('#fill-demo').click();
    await mobile.locator('#sign-in').click();
    await expect(mobile.locator('#mfa-panel')).toBeVisible();
    await mobile.evaluate(() => window.scrollTo(0, 0));
    await mobile.screenshot({ path: path.join(root, 'docs/screenshots/mobile.png') });
    await mobile.locator('#reset-company').click();
    await expect(mobile.locator('#event-total')).toHaveText('0 EVENTS');
  } finally {
    await mobileContext.close();
  }
} finally {
  const video = page.video();
  await context.close();
  console.log(`Recording: ${await video.path()}`);
  await browser.close();
}
