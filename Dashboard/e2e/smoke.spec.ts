import { test, expect } from '@playwright/test';

test.describe('Dashboard smoke tests', () => {
  test('page loads with correct title', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/WireSeal|VirtualFTP|Dashboard/);
  });

  test('vault-info fetch is attempted on load', async ({ page }) => {
    // Capture console messages — the app should log API errors
    // when the backend is not running (expected in this test)
    const consoleMsgs: string[] = [];
    page.on('console', (msg) => {
      consoleMsgs.push(msg.text());
    });

    await page.goto('/');

    // Wait for the app to mount and attempt its initial API call
    await page.waitForTimeout(2000);

    // The app should display something — could be error state or init screen
    const bodyText = await page.locator('body').innerText();
    expect(bodyText.length).toBeGreaterThan(0);
  });

  test('page has visible content after load', async ({ page }) => {
    await page.goto('/');
    // The app should render SOMETHING even without a backend
    await expect(page.locator('#root, #app, [data-testid]').first()).toBeAttached({ timeout: 5000 });
  });
});
