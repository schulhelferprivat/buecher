import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = fileURLToPath(new URL("../", import.meta.url));
const original = await readFile(join(root, "index.html"), "utf8");
const exposed = ["state", "els", "buildSafeTextLayer", "hasTextLayer", "updateTextOverlayForPage", "finalizeSelection", "getMaterialUrl", "needsMaterialSandbox", "createMaterialGroupItem", "openMaterial", "closeMaterialDialog", "returnToBookSelection", "selectBook", "resetFolderSelection"];
const html = original.replace("  function initApp() {", `  globalThis.audit = { ${exposed.join(", ")} };\n  function initApp() {`);
const worker = await readFile(join(root, "service-worker.js"), "utf8");
const handlers = {};
const deleted = [];
vm.runInNewContext(worker, {
  self: { addEventListener(type, handler) { handlers[type] = handler; }, clients: { claim() {} } },
  caches: { keys: async () => ["buecher-v4", "buecher-v5", "other-app-offline"], delete: async (key) => { deleted.push(key); return true; } },
});
let activation;
handlers.activate({ waitUntil(promise) { activation = promise; } });
await activation;
assert.deepEqual(deleted, ["buecher-v4"]);
console.log("PASS: activation preserves current and unrelated caches");

const requests = [];
const assets = new Map([
  ["/index.html", ["text/html", html]],
  ["/service-worker.js", ["application/javascript", worker]],
  ["/manifest.webmanifest", ["application/manifest+json", await readFile(join(root, "manifest.webmanifest"))]],
]);
for (const name of ["icon-32x32.png", "icon-192x192.png", "icon-512x512.png"]) {
  assets.set(`/${name}`, ["image/png", await readFile(join(root, name))]);
}
const server = createServer((request, response) => {
  requests.push(request.url);
  const asset = assets.get(request.url.split("?")[0]);
  response.writeHead(asset ? 200 : 404, { "Content-Type": asset ? asset[0] : "text/plain" });
  response.end(asset ? asset[1] : "Not found");
});
const profile = await mkdtemp(join(tmpdir(), "buecher-security-"));
let browser;
let socket;
try {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;
  const executable = process.env.BROWSER_PATH || "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge";
  browser = spawn(executable, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
  const endpoint = await new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(`Browser did not start: ${output.slice(-1500)}`)), 15000);
    browser.on("error", (error) => { clearTimeout(timeout); reject(error); });
    browser.stderr.on("data", (data) => {
      output += data.toString();
      const match = output.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
  });
  const debugOrigin = endpoint.replace(/^ws:/, "http:").split("/devtools/")[0];
  const targets = await (await fetch(`${debugOrigin}/json/list`)).json();
  socket = new WebSocket(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    const task = pending.get(message.id);
    if (!task) return;
    pending.delete(message.id);
    clearTimeout(task.timeout);
    if (message.error) task.reject(new Error(JSON.stringify(message.error)));
    else task.resolve(message.result);
  });
  function cdp(method, params = {}) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`Timed out: ${method}`)); }, 20000);
      pending.set(id, { resolve, reject, timeout });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  }
  await cdp("Page.enable");
  await cdp("Page.navigate", { url: `${base}/index.html` });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if (await evaluate("!!(window.audit && audit.els.materialDialog && document.readyState === 'complete' && navigator.serviceWorker.controller)")) break;
    } catch (error) {
      if (!/navigated|context|closed/.test(error.message)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  const results = await evaluate(`(${browserChecks.toString()})()`);
  results.forEach((result) => console.log(`PASS: ${result}`));
  assert.equal(requests.some((request) => request.startsWith("/probe")), false, "Untrusted text HTML requested resources");
  console.log("PASS: malicious text layers made no resource requests");
} finally {
  socket?.close();
  if (browser && browser.exitCode === null) {
    browser.kill("SIGTERM");
    await Promise.race([once(browser, "exit"), new Promise((resolve) => setTimeout(resolve, 3000))]);
    if (browser.exitCode === null) browser.kill("SIGKILL");
  }
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}

async function browserChecks() {
  const results = [];
  const check = (condition, message) => { if (!condition) throw new Error(message); };
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const { state, els } = audit;
  await delay(100);
  els.startScreen.hidden = true;
  const malicious = `<div class="textLayer" onclick="window.injected=true" style="background:url('/probe-root')">
    <div id="hostile" style="position:absolute;left:10px;top:20px;width:120px;height:20px;font-size:16px;transform:scaleX(1);background:url('/probe-style')" onmouseover="window.injected=true">Hello <span>world</span><br></div>
    <script>window.injected=true</script><img src="/probe-img" onerror="window.injected=true">
    <iframe src="/probe-frame"></iframe><link rel="stylesheet" href="/probe-css">
    <svg onload="window.injected=true"><image href="/probe-svg" /></svg>
    <object data="/probe-object"></object><style>@import '/probe-import';</style>
    <div style="position:fixed;left:var(--attack);transform:var(--attack)"></div>
  </div>`;
  const data = { html: malicious, width: 200, height: 100 };
  const safe = audit.buildSafeTextLayer(data);
  document.body.appendChild(safe);
  check(safe.textContent.trim() === "Hello world", "Text changed or active element content survived");
  check(!safe.querySelector("script,img,iframe,svg,object,style,link"), "Active elements survived");
  check(Array.from(safe.querySelectorAll("*")).every((node) => Array.from(node.attributes).every((attribute) => attribute.name === "style")), "Unsafe attributes survived");
  check(!safe.outerHTML.includes("url(") && !safe.outerHTML.includes("var(") && !safe.outerHTML.includes("fixed"), "Unsafe CSS survived");
  safe.remove();
  for (const width of [0, -1, Infinity, NaN, "Infinity"]) {
    check(audit.buildSafeTextLayer({ ...data, width }) === null, "Invalid dimensions accepted");
  }
  state.pageDataCache.set(1, data);
  check(await audit.hasTextLayer(1), "Valid text layer unavailable");
  const container = document.createElement("div");
  container.style.cssText = "position:fixed;left:0;top:0;width:400px;height:200px";
  const img = document.createElement("img");
  img.style.cssText = "width:400px;height:200px";
  img.dataset.page = "1";
  container.appendChild(img);
  document.body.appendChild(container);
  await audit.updateTextOverlayForPage(1, container, img);
  const overlay = container.querySelector(".text-overlay");
  const textNode = overlay.querySelector(".textLayer div");
  let box = textNode.getBoundingClientRect();
  check(Math.abs(box.left - 20) < 1 && Math.abs(box.top - 40) < 1 && Math.abs(box.width - 240) < 1, "Text geometry not preserved at 2x zoom");
  let copied = "";
  Object.defineProperty(navigator.clipboard, "writeText", { configurable: true, value: async (text) => { copied = text; } });
  audit.finalizeSelection({ container, overlay, rect: container.getBoundingClientRect(), startX: 15, startY: 35 }, 265, 85);
  await delay(20);
  check(copied === "Hello world", `Text selection failed: ${copied}`);
  img.style.width = "200px";
  img.style.height = "100px";
  await audit.updateTextOverlayForPage(1, container, img);
  box = container.querySelector(".textLayer div").getBoundingClientRect();
  check(Math.abs(box.left - 10) < 1 && Math.abs(box.top - 20) < 1, "Text geometry not preserved at 1x zoom");
  await delay(100);
  check(!window.injected, "Text HTML executed JavaScript");
  container.remove();
  results.push("text sanitization, finite dimensions, layout at two zoom levels and copying");

  for (const url of ["javascript:alert(1)", "java\nscript:alert(1)", "data:text/html,<script>alert(1)</script>", "blob:" + location.origin + "/forged", "file:///etc/passwd"]) {
    check(audit.getMaterialUrl({ url }) === "", `Unsafe URL allowed: ${url}`);
  }
  const external = { url: "https://example.com/lesson", name: "Website" };
  check(audit.getMaterialUrl(external) === external.url && !audit.needsMaterialSandbox(external, external.url), "External HTTPS link regressed");
  const local = { url: location.origin + "/lesson.html" };
  check(audit.needsMaterialSandbox(local, audit.getMaterialUrl(local)), "Same-origin HTML not isolated");
  const materialScript = `
    const blocked = {};
    for (const [key, action] of Object.entries({ parent: () => parent.document.body, storage: () => localStorage.getItem('secret'), indexedDB: () => indexedDB.open('lehrbuecher-viewer') })) {
      try { action(); blocked[key] = false; } catch { blocked[key] = true; }
    }
    try { blocked.popup = window.open('about:blank') === null; } catch { blocked.popup = true; }
    try { top.location.href = '/probe-navigation'; blocked.navigation = false; } catch { blocked.navigation = true; }
    parent.postMessage({ auditSandbox: true, blocked }, '*');
  `;
  const file = new File([`<html><body><script>${materialScript}</script></body></html>`], "exercise.html", { type: "text/html" });
  state.basePath = "sample";
  state.fileMap.set("sample/media/exercise.html", file);
  const entry = { file: "exercise.html", name: "Exercise", extension: "text/html" };
  const material = audit.createMaterialGroupItem({ title: "Exercise", entries: [entry] });
  document.body.appendChild(material);
  const button = material.querySelector("button.material-format");
  check(button && !material.querySelector("a[href]"), "Sandbox material exposes a direct link");
  const receive = () => new Promise((resolve, reject) => {
    const timer = setTimeout(() => { window.removeEventListener("message", handler); reject(new Error("No sandbox response")); }, 3000);
    const handler = (event) => {
      if (!event.data?.auditSandbox || event.source !== state.materialFrame?.contentWindow) return;
      clearTimeout(timer);
      window.removeEventListener("message", handler);
      resolve({ ...event.data, origin: event.origin });
    };
    window.addEventListener("message", handler);
  });
  button.focus();
  let response = receive();
  button.click();
  const report = await response;
  check(report.origin === "null", "Sandbox retained viewer origin");
  check(Object.values(report.blocked).every(Boolean), `Sandbox isolation failed: ${JSON.stringify(report)}`);
  check(state.materialFrame.getAttribute("sandbox") === "allow-scripts", "Unexpected sandbox permissions");
  const oldUrl = state.materialObjectUrl;
  const oldPage = state.currentPage;
  document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  check(state.currentPage === oldPage, "Viewer navigated behind dialog");
  els.materialClose.click();
  check(!els.materialDialog.open && !state.materialFrame && !els.materialDialog.querySelector("iframe"), "Frame survived close");
  check(document.activeElement === button, "Focus not restored");
  let revoked = false;
  try { await fetch(oldUrl); } catch { revoked = true; }
  check(revoked, "Temporary material URL was not revoked");
  for (const key of ["Enter", " "]) {
    response = receive();
    material.focus();
    material.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
    await response;
    els.materialDialog.dispatchEvent(new Event("cancel", { cancelable: true }));
    check(!els.materialDialog.open, "Cancel did not close dialog");
  }
  response = receive();
  material.click();
  await response;
  audit.returnToBookSelection();
  check(!els.materialDialog.open && !state.materialFrame, "Returning to books retained material");
  results.push("sandbox scripts run while parent, storage, popups and top navigation are blocked");
  results.push("format button, card click, Enter, Space, close, cancel, focus and URL cleanup");

  const pdf = new File(["%PDF-1.4"], "worksheet.pdf", { type: "application/pdf" });
  state.fileMap.set("sample/media/worksheet.pdf", pdf);
  const pdfEntry = { file: "worksheet.pdf", name: "Worksheet", extension: "PDF", page: 3 };
  const pdfUrl = audit.getMaterialUrl(pdfEntry);
  check(pdfUrl.endsWith("#page=3") && !audit.needsMaterialSandbox(pdfEntry, pdfUrl), "PDF handling regressed");
  const pdfItem = audit.createMaterialGroupItem({ title: "Worksheet", entries: [pdfEntry] });
  check(pdfItem.querySelector("a[target='_blank']"), "PDF link regressed");
  for (const [name, type] of [["worksheet.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"], ["archive.zip", "application/zip"]]) {
    state.fileMap.set(`sample/media/${name}`, new File(["probe"], name, { type }));
    const candidate = { file: name };
    check(!audit.needsMaterialSandbox(candidate, audit.getMaterialUrl(candidate)), `Office/archive material handling regressed: ${name}`);
  }
  for (const [name, type] of [["hidden.pdf", "text/html"], ["vector.svg", "image/svg+xml"], ["page.xhtml", "application/xhtml+xml"]]) {
    state.fileMap.set(`sample/media/${name}`, new File(["probe"], name, { type }));
    const candidate = { file: name };
    check(audit.needsMaterialSandbox(candidate, audit.getMaterialUrl(candidate)), `Active file type not isolated: ${name}`);
  }
  let opened;
  const originalOpen = window.open;
  window.open = (...args) => { opened = args; };
  audit.openMaterial(external);
  check(opened[0] === external.url && opened[2] === "noopener", "External opening regressed");
  audit.openMaterial(pdfEntry);
  check(opened[0] === pdfUrl, "PDF opening regressed");
  window.open = originalOpen;
  els.startScreen.hidden = true;
  response = receive();
  audit.openMaterial(entry);
  await response;
  state.fileMap.set("sample/book.json", new File([JSON.stringify({ title: "Next book", pagesCount: 1 })], "book.json", { type: "application/json" }));
  await audit.selectBook({ basePath: "sample", format: "legacy" });
  check(!els.materialDialog.open && !state.materialFrame, "Selecting a book retained material");
  response = receive();
  audit.openMaterial(entry);
  await response;
  await audit.resetFolderSelection();
  check(!els.materialDialog.open && !state.materialFrame && !state.materialObjectUrl, "Reset retained material");
  material.remove();
  results.push("URL validation, MIME detection, PDF/external links, book switching and reset");
  return results;
}
