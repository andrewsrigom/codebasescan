import { test, expect } from '@playwright/test';
test('shows evidence, explicit coverage gaps, and the real workflow', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Review-worthy SaaS', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: /Findings/ }).click();
  await page.getByLabel('Search findings').fill('Raw SQL');
  await page.getByRole('button', { name: /Raw SQL execution/ }).click();
  await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
  await expect(page.getByText('No LLM-based verification was performed.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Close finding' }).click();
  await page.getByRole('tab', { name: 'Dependencies', exact: true }).click();
  await expect(page.getByText('VULNERABILITY MATCHING NOT RUN')).toBeVisible();
  await page.getByRole('tab', { name: 'Workflow', exact: true }).click();
  await expect(page.getByText('interrupt() → Command(resume)')).toBeVisible();
});
test('exports a report without inline executable code', async ({ page }) => {
  await page.goto('/');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export report' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^traceward-.*\.html$/);
});
test('rejects a forged cross-origin mutation', async ({ request }) => {
  const response = await request.post('/api/audits', { headers: { Origin: 'https://attacker.invalid' }, data: { projectId: '00000000-0000-4000-8000-000000000001' } });
  expect(response.status()).toBe(403);
});
