// UI tests against coptimizer -demo: a simulated PC that needs no
// Administrator rights and reads nothing real. Run with scripts\test.ps1 -UI,
// which builds dist\coptimizer.exe first. Screenshots go to .tmp\e2e.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shots = path.join(repo, '.tmp', 'e2e');

let server;
let link;
let browser;

before(async () => {
  mkdirSync(shots, { recursive: true });
  server = spawn(path.join(repo, 'dist', 'coptimizer.exe'), ['-demo', '-no-browser'], { stdio: ['pipe', 'pipe', 'inherit'] });
  link = await new Promise((resolve, reject) => {
    let out = '';
    server.stdout.on('data', (chunk) => {
      out += chunk;
      const m = /One-time link: (\S+)/.exec(out);
      if (m) resolve(m[1]);
    });
    server.on('exit', (code) => reject(new Error(`the server exited with code ${code}`)));
    setTimeout(() => reject(new Error('the server printed no link')), 15000);
  });
  // An installed browser; COPTIMIZER_E2E_CHANNEL can pick another (msedge, chromium).
  browser = await chromium.launch({ channel: process.env.COPTIMIZER_E2E_CHANNEL ?? 'chrome' });
});

after(async () => {
  await browser?.close();
  server?.kill();
});

function watchForErrors(page) {
  const errors = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  return errors;
}

test('scan the demo PC and explore the result', async () => {
  const page = await browser.newPage({ viewport: { width: 1280, height: 860 } });
  const errors = watchForErrors(page);

  await page.goto(link);
  await page.getByRole('heading', { name: 'Overview' }).waitFor();
  assert.equal(new URL(page.url()).hash, '#/', 'the one-time code must leave the address bar');
  await page.locator('#rights', { hasText: 'Demo' }).waitFor();
  await page.locator('#conn', { hasText: 'Live' }).waitFor();
  const drives = page.locator('.drive');
  assert.equal(await drives.count(), 3);
  await page.screenshot({ path: path.join(shots, '1-start.png') });

  await drives.first().getByRole('button', { name: 'Scan' }).click();
  await page.getByRole('heading', { name: /Scanning C:\\/ }).waitFor();
  await page.waitForFunction(() => parseInt(document.querySelector('.big')?.textContent ?? '0', 10) > 0);
  await page.screenshot({ path: path.join(shots, '2-scanning.png') });
  await page.getByRole('heading', { name: /Scan of C:\\ finished in/ }).waitFor({ timeout: 60000 });
  await page.getByRole('heading', { name: /Biggest folders on C:\\/ }).waitFor();
  await page.screenshot({ path: path.join(shots, '3-done.png'), fullPage: true });

  await page.getByRole('link', { name: 'Explore the results' }).click();
  await page.getByRole('heading', { name: 'Explorer' }).waitFor();
  for (const name of ['Users', 'Demo', 'AppData', 'Local']) {
    await page.locator('a.row', { hasText: name }).first().click();
    await page.locator('.crumb.current', { hasText: name }).waitFor();
  }
  assert.match(await page.locator('a.row').first().innerText(), /npm-cache/, 'the largest folder comes first');
  await page.screenshot({ path: path.join(shots, '4-explorer.png'), fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.screenshot({ path: path.join(shots, '5-explorer-dark.png') });
  await page.emulateMedia({ colorScheme: 'light' });

  // A junction is listed, marked, and not a link to follow.
  await page.locator('.crumb', { hasText: 'Users' }).click();
  const junction = page.locator('.row', { hasText: 'All Users' });
  await junction.waitFor();
  assert.match(await junction.innerText(), /link, not followed/);
  assert.equal(await junction.evaluate((el) => el.tagName), 'DIV');

  // Findings: the totals, a card with its how-to, growth, a cache-like folder.
  await page.getByRole('link', { name: 'Findings' }).click();
  await page.getByRole('heading', { name: 'Findings' }).waitFor();
  await page.locator('.tile', { hasText: 'Safe to clean' }).waitFor();
  const npm = page.locator('article[data-id="dev.npm-cache"]');
  await npm.waitFor();
  assert.match(await npm.innerText(), /npm cache/);
  await npm.locator('summary').click();
  assert.equal(await npm.locator('.how code').first().innerText(), 'npm cache clean --force');
  // Locations sit in collapsed details: textContent reads them anyway.
  assert.match(await page.locator('article[data-id="other.growth"]').textContent(), /npm-cache\\_cacache.*grew \d/);
  assert.match(await page.locator('article[data-id="other.unrecognized"]').textContent(), /VendorSync\\VideoCachelooks like a cache/);
  await page.screenshot({ path: path.join(shots, '6-findings.png'), fullPage: true });

  // Filtering by risk shows only that kind.
  await page.locator('.tile', { hasText: 'Safe to clean' }).click();
  assert.equal(await page.locator('article.finding:not(.risk-safe)').count(), 0);
  assert.ok((await page.locator('article.finding.risk-safe').count()) > 5);
  await page.locator('.tile', { hasText: 'Safe to clean' }).click();

  // What Windows reports, and DISM's analysis on request.
  const system = page.locator('.system-list');
  await system.getByText(/hiberfil\.sys takes/).waitFor();
  await system.getByText('Ubuntu-24.04').waitFor();
  await system.getByRole('button', { name: 'Analyze' }).click();
  await system.getByText(/could be cleaned up/).waitFor({ timeout: 20000 });
  await page.screenshot({ path: path.join(shots, '7-system.png') });

  // The overview now leads to the findings.
  await page.getByRole('link', { name: 'Overview' }).click();
  await page.getByRole('heading', { name: 'Biggest findings' }).waitFor();
  assert.match(await page.locator('.reclaim').innerText(), /Safe to clean: \d/);
  await page.screenshot({ path: path.join(shots, '8-overview-findings.png'), fullPage: true });

  assert.deepEqual(errors, [], 'the page logged errors');
  await page.close();
});

test('a link that was used already does not sign in', async () => {
  const page = await browser.newPage();
  await page.goto(link);
  await page.getByRole('heading', { name: 'This page needs a new link' }).waitFor();
  await page.close();
});
