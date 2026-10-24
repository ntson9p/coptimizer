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
let output = '';

before(async () => {
  mkdirSync(shots, { recursive: true });
  server = spawn(path.join(repo, 'dist', 'coptimizer.exe'), ['-demo', '-no-browser'], { stdio: ['pipe', 'pipe', 'inherit'] });
  server.stdout.on('data', (chunk) => {
    output += chunk;
  });
  link = await new Promise((resolve, reject) => {
    server.stdout.on('data', () => {
      const m = /One-time link: (\S+)/.exec(output);
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

// newLink asks the server's console for another one-time link, as typing L
// in its window does.
async function newLink() {
  const seen = output.length;
  server.stdin.write('l\n');
  for (let i = 0; i < 100; i++) {
    const m = /New one-time link: (\S+)/.exec(output.slice(seen));
    if (m) return m[1];
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('the server printed no new link');
}

// tab is a link of the navigation bar.
function tab(page, name) {
  return page.locator('#tabs').getByRole('link', { name, exact: true });
}

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

test('clean up the demo PC, preview first', async () => {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = watchForErrors(page);
  await page.goto(await newLink());
  await page.locator('#conn', { hasText: 'Live' }).waitFor();
  await tab(page, 'Findings').click();
  const dialog = page.locator('dialog.cleanup');

  // The npm cache: a preview that changes nothing, then the real cleanup.
  const npm = page.locator('article[data-id="dev.npm-cache"]');
  await npm.getByRole('button', { name: 'Clean up…' }).click();
  await dialog.getByText(/Deletes [\d,]+ files/).waitFor({ timeout: 30000 });
  assert.match(await dialog.innerText(), /npm-cache/);
  await page.screenshot({ path: path.join(shots, '9-preview.png') });
  await dialog.getByRole('button', { name: 'Delete these files' }).click();
  await dialog.getByText(/Done: .* more free space/).waitFor({ timeout: 60000 });
  await page.screenshot({ path: path.join(shots, '10-cleaned.png') });
  await dialog.getByRole('button', { name: 'Close' }).click();
  // Its folder is measured again, and the finding goes.
  await npm.waitFor({ state: 'detached', timeout: 30000 });

  // VS Code's caches wait until VS Code is closed (the demo closes it soon).
  const editor = page.locator('article[data-id="dev.editor-caches"]');
  await editor.getByRole('button', { name: 'Clean up…' }).click();
  await dialog.getByText('Close Visual Studio Code first, then check again.').waitFor({ timeout: 30000 });
  assert.equal(await dialog.getByRole('button', { name: 'Delete these files' }).isDisabled(), true);
  await page.screenshot({ path: path.join(shots, '11-close-first.png') });
  await page.waitForTimeout(3200);
  await dialog.getByRole('button', { name: 'Check again' }).click();
  await dialog.getByRole('button', { name: 'Delete these files' }).and(page.locator(':enabled')).waitFor({ timeout: 30000 });
  await dialog.getByRole('button', { name: 'Cancel' }).click();

  // Simulation mode: the same cleanup only says what it would do.
  await tab(page, 'Activity').click();
  await page.getByLabel('Simulation mode').check();
  await page.locator('#simulate', { hasText: 'Simulation' }).waitFor();
  await tab(page, 'Findings').click();
  await editor.getByRole('button', { name: 'Clean up…' }).click();
  await dialog.getByText(/Simulation mode is on/).waitFor({ timeout: 30000 });
  await dialog.getByRole('button', { name: 'Simulate' }).click();
  await dialog.getByText(/Simulation finished: .* would have been deleted/).waitFor({ timeout: 60000 });
  await dialog.getByRole('button', { name: 'Close' }).click();
  await tab(page, 'Activity').click();
  await page.getByLabel('Simulation mode').uncheck();
  await page.locator('#simulate').waitFor({ state: 'hidden' });
  await tab(page, 'Findings').click();
  assert.equal(await editor.count(), 1, 'a simulation must not clean anything');

  // The Recycle Bin, emptied through Windows (simulated here).
  await page.locator('article[data-id="personal.recycle-bin"]').getByRole('button', { name: 'Empty the Recycle Bin…' }).click();
  await dialog.getByText(/Empties your Recycle Bin on C:, with 40 items/).waitFor({ timeout: 30000 });
  await dialog.getByRole('button', { name: 'Empty the Recycle Bin' }).click();
  await dialog.getByText(/the Recycle Bin is empty/).waitFor({ timeout: 30000 });
  await dialog.getByRole('button', { name: 'Close' }).click();

  // DISM's cleanup: the exact command, no way to stop it, live progress.
  await page.locator('article[data-id="system.component-store"]').getByRole('button', { name: 'Clean up with DISM…' }).click();
  await dialog.locator('pre.command', { hasText: 'dism.exe /Online /English /Cleanup-Image /StartComponentCleanup' }).waitFor({ timeout: 30000 });
  await dialog.getByRole('button', { name: 'Run the cleanup' }).click();
  await dialog.getByText("This can't be stopped safely once it has started.").waitFor();
  assert.equal(await dialog.getByRole('button', { name: 'Stop' }).count(), 0);
  await page.screenshot({ path: path.join(shots, '12-dism.png') });
  await dialog.getByText(/Done: .* more free space/).waitFor({ timeout: 30000 });
  await dialog.getByText(/Scan C: again/).waitFor();
  await dialog.getByRole('link', { name: 'See Activity' }).click();

  // Activity: this session's cleanups and the history.
  await page.getByRole('heading', { name: 'Activity' }).waitFor();
  await page.locator('.job-list .job').nth(3).waitFor();
  const history = page.locator('.table.history');
  await history.locator('.row:not(.head)').nth(3).waitFor();
  assert.match(await history.innerText(), /npm cache/i);
  assert.match(await history.innerText(), /Simulation/);
  assert.match(await page.locator('.card', { hasText: 'History' }).innerText(), /freed in total by 3 cleanups/);
  await page.screenshot({ path: path.join(shots, '13-activity.png'), fullPage: true });

  assert.deepEqual(errors, [], 'the page logged errors');
  await page.close();
});

test('a link that was used already does not sign in', async () => {
  const page = await browser.newPage();
  await page.goto(link);
  await page.getByRole('heading', { name: 'This page needs a new link' }).waitFor();
  await page.close();
});
