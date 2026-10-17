import { test, expect } from '@playwright/test';

async function ready(page) {
  await page.goto('/company.html');
  await expect(page.locator('#fill-demo')).toBeEnabled();
}
async function signIn(page) {
  await page.locator('#fill-demo').click();
  await page.locator('#sign-in').click();
  await expect(page.locator('#mfa-panel')).toBeVisible();
  await expect(page.locator('#password')).toHaveValue('');
}
async function mfa(page) {
  await page.locator('#mfa-code').fill('123456');
  await page.locator('#mfa-submit').click();
  await expect(page.locator('#workspace-panel')).toBeVisible();
}

test('sign-in, server authorization, tamper detection and reset', async ({page,baseURL}) => {
  const errors=[], external=[];
  page.on('pageerror',error => errors.push(error.message));
  page.on('request',request => { if (!request.url().startsWith(`${baseURL}/`)) external.push(request.url()); });
  await ready(page); await signIn(page); await mfa(page);
  await page.locator('#open-resource').click();
  await expect(page.locator('#resource-result')).toContainText('Employee workspace authorized');
  await page.locator('#try-restricted').click();
  await expect(page.locator('#resource-result')).toContainText('Server denied access');
  await expect(page.locator('#workspace-panel')).toBeVisible();
  await page.locator('#check-receipt').click();
  await expect(page.locator('#proof-result')).toContainText('Altered score rejected');
  await expect(page.locator('#event-total')).toHaveText('2 EVENTS');
  await page.locator('#reset-company').click();
  await expect(page.locator('#event-total')).toHaveText('0 EVENTS');
  await expect(page.locator('#receipt-status')).toHaveText('Waiting for a decision');
  await expect(page.locator('#access-role')).toHaveText('anonymous');
  await expect(page.locator('#workspace-panel')).toBeHidden();
  expect(errors).toEqual([]); expect(external).toEqual([]);
  expect(await page.evaluate(() => [localStorage.length,sessionStorage.length,document.cookie])).toEqual([0,0,'']);
});

test('unusual successful login with zero failures and benign single changes', async ({page}) => {
  await ready(page);
  await page.locator('#prepare-unusual').click(); await page.locator('#sign-in').click();
  await expect(page.locator('#mfa-panel')).toBeVisible();
  await expect(page.locator('#failure-count')).toHaveText('0');
  await expect(page.locator('#context-guard-status')).toContainText('Context safeguard triggered');
  await mfa(page);
  await expect(page.locator('#context-guard-status')).toContainText('Earlier context evidence');
  for (const context of ['vpn','travel','new_device']) {
    await page.locator('#reset-company').click(); await expect(page.locator('#event-total')).toHaveText('0 EVENTS');
    await expect(page.locator('#fill-demo')).toBeEnabled();
    await page.locator('#login-context').selectOption(context); await signIn(page);
    await expect(page.locator('#context-guard-status')).toContainText('No combined-context safeguard');
  }
});

test('attack replay, throttle, missing evidence and viewport boundaries', async ({page},testInfo) => {
  await ready(page);
  for (const [id,amount] of [['run-brute','20'],['run-spray','18'],['run-distributed','12']]) {
    await page.locator(`#${id}`).click();
    await expect(page.locator('#event-total')).toHaveText(`${amount} EVENTS`);
    await expect(page.locator('#risk-action')).toContainText('review');
    await page.locator('#reset-company').click(); await expect(page.locator('#event-total')).toHaveText('0 EVENTS');
    await expect(page.locator('#fill-demo')).toBeEnabled();
  }
  await page.locator('#password').fill('wrong-example'); await page.locator('#sign-in').click();
  await expect(page.locator('#login-backoff')).toBeVisible();
  await expect(page.locator('#sign-in')).toBeDisabled();
  await expect(page.locator('#sign-in')).toBeEnabled({timeout:4000});
  await page.locator('#login-context').selectOption('cold_start');
  await page.locator('#fill-demo').click(); await page.locator('#sign-in').click();
  await expect(page.locator('#data-quality')).toHaveText('Insufficient');
  await expect(page.locator('#risk-score')).toHaveText('—');
  await expect(page.locator('#workspace-panel')).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator('#reset-company').click(); await expect(page.locator('#event-total')).toHaveText('0 EVENTS');
  await page.screenshot({path:testInfo.outputPath('portal.png'),fullPage:true});
});

test('field guide and keyboard navigation', async ({page}) => {
  await ready(page);
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link',{name:'Skip to sign in'})).toBeFocused();
  await page.keyboard.press('Enter');
  await page.getByRole('link',{name:'Datathon field guide',exact:true}).click();
  await expect(page.locator('h1')).toContainText('Less identity exposure');
  await expect(page.locator('main')).toContainText('release remains blocked');
  await expect(page.locator('#ibm-z')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
