import { test, expect } from '@playwright/test';
test('shows evidence, explicit coverage gaps, and the real workflow', async ({ page }) => {
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Review-worthy SaaS', exact: true }),
  ).toBeVisible();
  await page.getByRole('tab', { name: /Findings/ }).click();
  await page.getByLabel('Search findings').fill('Raw SQL');
  await page.getByRole('button', { name: /Raw SQL execution/ }).click();
  await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
  await expect(
    page.getByText('No LLM-based verification was performed.', { exact: false }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Close finding' }).click();
  await page.getByRole('tab', { name: 'Project map', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Project map' })).toBeVisible();
  await expect(page.getByLabel('Search project entry points')).toBeVisible();
  await page.getByRole('tab', { name: 'Dependencies', exact: true }).click();
  await expect(page.getByText(/OSV (?:skipped|not run|completed)/i)).toBeVisible();
  await page.getByRole('tab', { name: 'Checklist', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Security control checklist' })).toBeVisible();
  await expect(page.getByText('GAP CANDIDATE', { exact: false }).first()).toBeVisible();
  await page.getByRole('tab', { name: 'Investigations', exact: true }).click();
  await expect(page.getByText('No model investigation was performed')).toBeVisible();
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
  const response = await request.post('/api/audits', {
    headers: { Origin: 'https://attacker.invalid' },
    data: { projectId: '00000000-0000-4000-8000-000000000001' },
  });
  expect(response.status()).toBe(403);
});

test('shows a bounded source estimate before an audit can be queued', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'New audit' }).click();
  await expect(page.getByText('Pre-audit scope estimate', { exact: true })).toBeVisible();
  await expect(page.getByText(/supported files/)).toBeVisible();
  await expect(page.getByRole('button', { name: /Queue audit/ })).toBeEnabled();
});

test('supports keyboard tabs and keeps collapsed mobile navigation named', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');

  for (const name of [
    'Traceward overview',
    'Overview',
    'Audit history',
    'Projects',
    'Methodology',
    'Local settings',
  ])
    await expect(page.getByRole('link', { name, exact: true })).toBeVisible();

  const overview = page.getByRole('tab', { name: 'Overview', exact: true });
  await overview.focus();
  await overview.press('ArrowRight');
  await expect(page.getByRole('tab', { name: /Findings/ })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.getByLabel('Search findings')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
});
