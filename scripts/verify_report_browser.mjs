// Open a TenantTrace HTML report from disk in a headless Chromium browser that is already installed
// (Microsoft Edge or Google Chrome), with name resolution and proxying disabled so nothing can be
// fetched, then click through it like an investigator: a detection marker on the coverage chart,
// then the first evidence record, then check the raw record and its verification. Also checks
// keyboard access (Enter opens a timeline step, Escape closes the panel) and that the page made no
// network request at all. Writes a screenshot of the raw-record view.
//
//   node scripts/verify_report_browser.mjs <report.html> <screenshot.png> [rule-id]
//
// Exit code 0 when every check passes, 1 when one fails, 2 when no browser is installed.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [, , reportArg, shotArg, ruleArg] = process.argv;
if (!reportArg || !shotArg) {
  console.error("usage: node scripts/verify_report_browser.mjs <report.html> <screenshot.png> [rule-id]");
  process.exit(2);
}
const rule = ruleArg || "TT-MAIL-001";
const candidates = [
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/microsoft-edge",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
];
const browser = candidates.find((p) => existsSync(p));
if (!browser) {
  console.log(JSON.stringify({ skipped: "no installed Edge or Chrome found" }));
  process.exit(2);
}

const port = 9300 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), "tt-browser-"));
const proc = spawn(browser, [
  "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
  `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
  "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9", "--window-size=1400,1000",
  "about:blank",
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = { browser, checks: [] };
let failed = false;
function check(name, ok, detail = "") {
  results.checks.push({ name, ok: !!ok, detail });
  if (!ok) failed = true;
}

async function target() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await sleep(250);
  }
  throw new Error("browser did not start");
}

async function main() {
  const ws = new WebSocket(await target());
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0;
  const pending = new Map();
  const requests = [];
  let loaded = false;
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    if (msg.method === "Network.requestWillBeSent") requests.push(msg.params.request.url);
    if (msg.method === "Page.loadEventFired") loaded = true;
  };
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const evalJs = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
  const click = async (x, y) => {
    const hit = await evalJs(`(() => { const e = document.elementFromPoint(${x}, ${y}); return e ? e.tagName + "." + (e.getAttribute("class") || "") : "none"; })()`);
    results.lastHit = hit;
    await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", buttons: 1, clickCount: 1 });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", buttons: 0, clickCount: 1 });
  };
  const key = async (k, code) => {
    const vk = k === "Enter" ? 13 : 27;
    await send("Input.dispatchKeyEvent", { type: "rawKeyDown", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk });
    const CR = String.fromCharCode(13);
    if (k === "Enter") await send("Input.dispatchKeyEvent", { type: "char", key: k, code, text: CR, unmodifiedText: CR });
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk });
  };
  const centre = (sel) => evalJs(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return null;
    e.scrollIntoView({block: "center", behavior: "instant"}); const r = e.getBoundingClientRect(); return {x: r.x + r.width / 2, y: r.y + r.height / 2}; })()`);

  await send("Network.enable");
  await send("Page.enable");
  await send("Page.bringToFront");
  await send("Emulation.setFocusEmulationEnabled", { enabled: true });
  const url = pathToFileURL(resolve(reportArg)).href;
  await send("Page.navigate", { url });
  for (let i = 0; i < 80 && !loaded; i++) await sleep(100);
  await sleep(400);
  check("report rendered", await evalJs(`document.querySelectorAll("li.step").length > 0 && !!document.querySelector("svg.coverage")`));

  // 1. click the coverage-chart marker of the chosen rule's finding
  const markerSel = `svg.coverage circle.marker[aria-label*="${rule}"]`;
  const findingId = await evalJs(`(() => { const d = JSON.parse(document.getElementById("tt-data").textContent);
    const f = d.findings.find(x => x.rule_id === ${JSON.stringify(rule)}); return f ? f.id : null; })()`);
  const markerFallback = `svg.coverage circle.marker[aria-label*="${findingId}"]`;
  const m = (await centre(markerSel)) || (await centre(markerFallback));
  check("coverage marker present for the finding", !!m, findingId || "");
  if (m) await click(m.x, m.y);
  await sleep(300);
  const title1 = await evalJs(`document.querySelector("aside.drawer #dr-title")?.textContent || ""`);
  check("marker click opens the finding", title1.length > 0, title1);

  // 2. click the first evidence record in the finding
  const row = await centre("aside.drawer tr.click");
  check("finding lists its evidence records", !!row);
  if (row) await click(row.x, row.y);
  await sleep(300);
  const view = await evalJs(`(() => ({
    title: document.querySelector("aside.drawer #dr-title")?.textContent || "",
    verify: document.querySelector("aside.drawer .verify")?.textContent || "",
    raw: (document.querySelector("aside.drawer pre.raw")?.textContent || "").slice(0, 120),
  }))()`);
  check("evidence click opens the raw record", view.raw.length > 20, view.title);
  check("raw record re-verified against its ingest hash", /matches/.test(view.verify), view.verify);
  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(shotArg, Buffer.from(shot.result.data, "base64"));

  // 3. keyboard: Escape closes, Enter on a focused timeline step opens it
  await key("Escape", "Escape");
  await sleep(200);
  check("Escape closes the panel", await evalJs(`!document.querySelector("aside.drawer")`));
  await evalJs(`(() => { const b = document.querySelector("li.step button.card"); b.scrollIntoView({block: "center", behavior: "instant"}); b.focus(); })()`);
  await key("Enter", "Enter");
  await sleep(300);
  check("Enter on a focused timeline step opens it", await evalJs(`!!document.querySelector("aside.drawer")`));

  // 4. no network traffic beyond the file itself
  const external = requests.filter((u) => !u.startsWith("file:") && !u.startsWith("data:") && u !== "about:blank");
  check("no network request was made", external.length === 0, external.slice(0, 3).join(" "));
  ws.close();
}

try {
  await main();
} catch (e) {
  check("browser session", false, String(e));
} finally {
  proc.kill();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* profile still locked */ }
}
console.log(JSON.stringify(results, null, 2));
process.exit(failed ? 1 : 0);
