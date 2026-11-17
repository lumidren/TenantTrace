// Inline the built JS and CSS into dist/index.html and write the Python package's template.
// The output must be byte-for-byte reproducible: CI rebuilds it and compares with the committed file.
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "..", "dist");
const target = join(here, "..", "..", "src", "tenanttrace", "report", "template.html");
let html = readFileSync(join(dist, "index.html"), "utf8");
const assets = join(dist, "assets");
const files = readdirSync(assets);

html = html.replace(/<script type="module" crossorigin src="\.\/assets\/([^"]+)"><\/script>/g, (_m, name) => {
  const js = readFileSync(join(assets, name), "utf8").replace(/<\/script/gi, "<\/script");
  return `<script type="module">${js}</script>`;
});
html = html.replace(/<link rel="stylesheet" crossorigin href="\.\/assets\/([^"]+)">/g, (_m, name) => {
  return `<style>${readFileSync(join(assets, name), "utf8")}</style>`;
});
// The finished report may not load or send anything: inline code and styles only, no connections.
const csp =
  `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; ` +
  `style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; frame-src 'none'; ` +
  `base-uri 'none'; form-action 'none'">`;
html = html.replace("<!--TT_CSP-->", csp);
if (/\.\/assets\//.test(html)) {
  throw new Error("an asset reference was not inlined: " + files.join(", "));
}
if (/(src|href)="https?:/i.test(html)) {
  throw new Error("the template references an external URL");
}
html = html.replace(/\r\n/g, "\n");
writeFileSync(target, html, "utf8");
console.log(`template written: ${target} (${html.length} chars)`);
