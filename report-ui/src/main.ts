import "./styles.css";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Dict = Record<string, any>;

const LEVELS = ["confirmed", "probable", "possible"] as const;
const LEVEL_RANK: Record<string, number> = { confirmed: 3, probable: 2, possible: 1 };
const SOURCE_SHORT: Record<string, string> = {
  entra_signin_interactive: "Entra sign-ins (interactive)",
  entra_signin_noninteractive: "Entra sign-ins (non-interactive)",
  entra_audit: "Entra audit log",
  ual_azuread_logon: "UAL: sign-in copies",
  ual_azuread: "UAL: directory changes",
  ual_exchange_admin: "UAL: Exchange admin",
  ual_mailbox_items: "UAL: mailbox items",
  ual_sharepoint: "UAL: SharePoint / OneDrive",
  ual: "Unified audit log export",
};
const GAP_LABEL: Record<string, string> = {
  missing: "not supplied",
  auditing_absent: "auditing absent",
  truncated: "truncated",
  ends_early: "ends early",
  retention: "retention cut",
  quiet: "unexplained quiet period",
  user_absent: "account absent",
  filtered: "filtered export",
};

let data: Dict;
let lastFocus: HTMLElement | null = null;

// ----------------------------------------------------------------------------- DOM helpers

type Child = Node | string | number | null | undefined | false | Child[];

function h(tag: string, attrs: Dict | null = null, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = String(v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
      else if (k === "html") el.innerHTML = String(v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  append(el, children);
  return el;
}

function append(el: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

const SVGNS = "http://www.w3.org/2000/svg";
function s(tag: string, attrs: Dict = {}, ...children: (SVGElement | string)[]): SVGElement {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null) continue;
    el.setAttribute(k, String(v));
  }
  for (const c of children) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return el;
}

function fmt(ts: string | undefined, withSeconds = false): string {
  if (!ts) return "";
  return ts.slice(0, withSeconds ? 19 : 16).replace("T", " ");
}

function levelBadge(level?: string): HTMLElement | null {
  if (!level) return null;
  return h("span", { class: `badge lv-${level}`, title: `Confidence: ${level}` }, level);
}

function labelBadge(label: string): HTMLElement {
  return label === "inference"
    ? h("span", { class: "badge lb-inference", title: "Inference: goes beyond the records and states its basis" },
        h("span", { class: "dot inference", "aria-hidden": "true" }), "Inference")
    : h("span", { class: "badge lb-observed", title: "Observed fact: read directly from the listed records" },
        h("span", { class: "dot observed", "aria-hidden": "true" }), "Observed fact");
}

function statusPill(status: string): HTMLElement {
  return h("span", { class: `st st-${status}` }, status.replace(/_/g, " "));
}

function short(sid: string): string {
  return SOURCE_SHORT[sid] || sid;
}

// ----------------------------------------------------------------------------- theme

function applyTheme(t: string): void {
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  else document.documentElement.removeAttribute("data-theme");
}

function storedTheme(): string {
  try {
    return localStorage.getItem("tt-theme") || "system";
  } catch {
    return "system";
  }
}

function cycleTheme(btn: HTMLElement): void {
  const order = ["system", "light", "dark"];
  const next = order[(order.indexOf(storedTheme()) + 1) % order.length];
  try {
    localStorage.setItem("tt-theme", next);
  } catch {
    /* storage unavailable: theme still changes for this view */
  }
  applyTheme(next);
  btn.textContent = `Theme: ${next}`;
}

// ----------------------------------------------------------------------------- header, nav, footer

function header(): HTMLElement {
  const c = data.case;
  const w = c.window || {};
  return h("header", { class: "top" },
    h("div", { class: "wrap" },
      h("div", { class: "brandline" },
        h("span", { html: '<svg class="logo" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4zm0 3.2 6 2.7V12c0 3.7-2.6 6.9-6 7.6-3.4-.7-6-3.9-6-7.6V7.9l6-2.7zm-1 3.8v4.6l3.6 2.2.9-1.5-2.9-1.7V9h-1.6z"/></svg>' }),
        `${data.tool.name} investigation report`),
      h("h1", null, `Account compromise investigation: ${c.user}`),
      h("div", { class: "meta" },
        h("span", null, h("b", null, "Case period "), `${fmt(c.case_start)} to ${fmt(c.case_end)} UTC`),
        h("span", null, h("b", null, "Collected "), `${fmt(c.collected_at)} UTC`),
        h("span", null, h("b", null, "Compromise window from "), `${fmt(w.start)} UTC (${w.method || "n/a"})`),
        h("span", null, h("b", null, "Generated "), `${fmt(data.generated_utc)} UTC`))));
}

function nav(): HTMLElement {
  const themeBtn = h("button", { class: "btn no-print", type: "button" }, `Theme: ${storedTheme()}`);
  themeBtn.addEventListener("click", () => cycleTheme(themeBtn));
  const links: [string, string][] = [["summary", "Summary"], ["coverage", "Coverage"], ["timeline", "Timeline"],
    ["findings", "Findings"], ["gaps", "Evidence gaps"], ["pivot", "Other accounts"], ["inputs", "Inputs"],
    ["method", "Method"]];
  return h("nav", { class: "tabs", "aria-label": "Report sections" },
    h("div", { class: "wrap" },
      links.map(([id, label]) => h("a", { href: `#${id}` }, label)),
      h("span", { class: "spacer" }),
      themeBtn,
      h("button", { class: "btn no-print", type: "button", onclick: () => window.print() }, "Print / PDF")));
}

function footer(): HTMLElement {
  const t = data.tool;
  return h("footer", { class: "foot" },
    h("div", { class: "wrap" },
      `${t.name} ${t.version} | rule set ${t.ruleset} | gap reference table ${t.reference_table} | event schema ${t.schema}. `,
      "This report was produced offline from the supplied exports; nothing was looked up online. ",
      "The case database holds every normalized event; this page embeds only the evidence it cites."));
}

// ----------------------------------------------------------------------------- summary

function summary(): HTMLElement {
  const sm = data.summary;
  const counts = sm.counts || {};
  const cov = data.coverage.summary || {};
  const kpi = (v: string | number, l: string) => h("div", { class: "kpi" }, h("div", { class: "v" }, String(v)), h("div", { class: "l" }, l));
  return h("section", { class: "block", id: "summary", "aria-labelledby": "h-summary" },
    h("h2", { id: "h-summary" }, "Executive summary"),
    h("div", { class: "panel" },
      h("p", { class: "headline" }, sm.headline),
      h("div", { class: "kpis" },
        kpi(counts.confirmed || 0, "confirmed findings"),
        kpi(counts.probable || 0, "probable findings"),
        kpi(counts.possible || 0, "possible findings"),
        kpi(data.pivot.length, "other accounts with the same indicators"),
        kpi((data.coverage.gaps || []).length, "evidence gaps"),
        kpi((cov.sources_present || []).length, "log sources supplied")),
      h("div", { class: "cols" },
        h("div", null, h("h3", null, "What the evidence shows"),
          sm.facts.length ? h("ul", null, sm.facts.map((f: string) => h("li", null, f))) : h("p", { class: "muted" }, "No findings at probable or confirmed level.")),
        h("div", { class: "limits" }, h("h3", null, "What the evidence cannot show"),
          sm.limits.length ? h("ul", null, sm.limits.map((f: string) => h("li", null, f))) : h("p", { class: "muted" }, "No evidence gaps were found in the supplied logs."))),
      sm.next_steps.length ? h("div", { style: "margin-top:12px" }, h("h3", { style: "font-size:14px;margin:0 0 6px" }, "Where to look next"),
        h("ul", { style: "margin:0;padding-left:18px" }, sm.next_steps.map((f: string) => h("li", null, f)))) : null));
}

// ----------------------------------------------------------------------------- coverage chart

function coverage(): HTMLElement {
  const cov = data.coverage;
  const sources: Dict[] = cov.sources || [];
  const lanes = cov.lanes || { series: {} };
  const start = Date.parse(((data.case.case_start || lanes.start) + "").slice(0, 10) + "T00:00:00Z");
  const endIso = data.case.collected_at || data.case.case_end;
  const end = Date.parse(endIso) || start + 86400000;
  const span = Math.max(end - start, 86400000);
  const W = 1000, left = 210, right = 16, top = 30, laneH = 34;
  const H = top + sources.length * laneH + 24;
  const x = (t: number) => left + ((t - start) / span) * (W - left - right);
  const root = s("svg", { class: "coverage", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-labelledby": "cov-title cov-desc" });
  root.appendChild(s("title", { id: "cov-title" }, "Evidence coverage by log source"));
  root.appendChild(s("desc", { id: "cov-desc" }, "One lane per log source across the case period, with daily record counts as bars, evidence gaps shaded and labelled, and detections marked by confidence."));
  const defs = s("defs");
  const pat = s("pattern", { id: "hatch", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" });
  pat.appendChild(s("rect", { width: 6, height: 6, style: "fill: var(--gap-bg)" }));
  pat.appendChild(s("line", { x1: 0, y1: 0, x2: 0, y2: 6, style: "stroke: var(--gap); stroke-width: 1.4; opacity: .55" }));
  defs.appendChild(pat);
  root.appendChild(defs);
  // date grid
  const days = Math.ceil(span / 86400000);
  const step = days > 120 ? 30 : days > 45 ? 14 : 7;
  for (let d = 0; d <= days; d += step) {
    const t = start + d * 86400000;
    const gx = x(t);
    root.appendChild(s("line", { class: "grid", x1: gx, x2: gx, y1: top - 6, y2: H - 20 }));
    root.appendChild(s("text", { x: gx + 2, y: top - 10 }, new Date(t).toISOString().slice(5, 10)));
  }
  const laneIndex: Record<string, number> = {};
  sources.forEach((src, i) => { laneIndex[src.source] = i; });
  sources.forEach((src, i) => {
    const y = top + i * laneH;
    root.appendChild(s("rect", { class: "lane-bg", x: left, y: y + 4, width: W - left - right, height: laneH - 8, rx: 3 }));
    root.appendChild(s("text", { class: "lane-label", x: 8, y: y + 17 }, short(src.source)));
    root.appendChild(s("text", { class: "lane-sub", x: 8, y: y + 29 },
      src.status === "present" ? `${src.events.toLocaleString()} records` : src.status.replace(/_/g, " ")));
    const series: Record<string, number> = (lanes.series || {})[src.source] || {};
    const max = Math.max(1, ...Object.values(series));
    for (const [day, n] of Object.entries(series)) {
      const t0 = Date.parse(day + "T00:00:00Z");
      const bh = Math.max(2, Math.sqrt(n / max) * (laneH - 10));
      const bar = s("rect", { class: "bar", x: x(t0) + 0.5, y: y + laneH - 5 - bh, width: Math.max(1.5, x(t0 + 86400000) - x(t0) - 1), height: bh, opacity: 0.85 });
      bar.appendChild(s("title", {}, `${short(src.source)}: ${n} record(s) on ${day}`));
      root.appendChild(bar);
    }
    if (src.status === "missing" && (src.alternatives_supplied || []).length) {
      root.appendChild(s("text", { class: "lane-sub", x: left + 8, y: y + 21 },
        `not supplied; the same evidence is covered by ${src.alternatives_supplied.map(short).join(", ")}`));
    } else if (src.status === "missing" || src.status === "auditing_absent") {
      const gx0 = src.status === "missing" ? left : x(Date.parse(src.covers_first) || start);
      const gx1 = src.status === "missing" ? W - right : x(Date.parse(src.covers_last) || end);
      root.appendChild(s("rect", { class: "gap", x: gx0, y: y + 4, width: Math.max(2, gx1 - gx0), height: laneH - 8, rx: 3 }));
      root.appendChild(s("text", { class: "gap-label", x: gx0 + 6, y: y + 21 }, GAP_LABEL[src.status]));
    } else if (src.status === "no_records") {
      root.appendChild(s("text", { class: "lane-sub", x: left + 8, y: y + 21 }, "supplied, no records (these records are only written when a change happens)"));
    }
  });
  // gaps with a period
  for (const g of cov.gaps || []) {
    if (g.kind === "missing" || g.kind === "auditing_absent") continue;
    const affected: string[] = (g.affects_sources && g.affects_sources.length) ? g.affects_sources : [g.source];
    const t0 = Date.parse(g.start) || start, t1 = Date.parse(g.end) || end;
    for (const sid of affected) {
      const i = laneIndex[sid];
      if (i === undefined) continue;
      const y = top + i * laneH;
      const r = s("rect", { class: "gap", x: x(t0), y: y + 4, width: Math.max(3, x(t1) - x(t0)), height: laneH - 8, rx: 3 });
      r.appendChild(s("title", {}, `${GAP_LABEL[g.kind] || g.kind}: ${g.statement}`));
      root.appendChild(r);
      root.appendChild(s("text", { class: "gap-label", x: Math.min(x(t0) + 4, W - right - 120), y: y + 15 }, GAP_LABEL[g.kind] || g.kind));
    }
  }
  // compromise window and collection time
  const ws = Date.parse(data.case.window?.start || "");
  if (ws) {
    root.appendChild(s("line", { class: "window", x1: x(ws), x2: x(ws), y1: top - 4, y2: H - 18 }));
    root.appendChild(s("text", { x: x(ws) + 4, y: H - 6, style: "fill: var(--inference); font-weight: 600" }, "compromise window"));
  }
  root.appendChild(s("line", { class: "collected", x1: x(end), x2: x(end), y1: top - 4, y2: H - 18 }));
  // detections
  const placed: Record<string, number[]> = {};
  const findings = [...data.findings].sort((a: Dict, b: Dict) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);
  for (const f of findings) {
    const ev = data.events[(f.suspect_event_ids || f.event_ids)[0]] || data.events[f.event_ids[0]];
    const sid = ev ? ev.source : "";
    const i = laneIndex[sid];
    if (i === undefined) continue;
    const t = Date.parse(f.suspect_first_ts || f.first_ts);
    const cx = x(t);
    const key = sid;
    placed[key] = placed[key] || [];
    let dy = 0;
    while (placed[key].some((px) => Math.abs(px - (cx + dy * 1000)) < 0.1)) dy++;
    const near = placed[key].filter((px) => Math.abs(px - cx) < 9).length;
    placed[key].push(cx);
    const cy = top + i * laneH + 13 + (near % 3) * 7;
    const m = s("circle", { class: `marker m-${f.level}`, cx, cy, r: 5.5, tabindex: 0, role: "button",
      "aria-label": `${f.level} finding ${f.id}: ${f.title} at ${fmt(f.suspect_first_ts || f.first_ts)}` });
    m.appendChild(s("title", {}, `${f.level.toUpperCase()} ${f.id}: ${f.summary}`));
    m.addEventListener("click", () => openFinding(f.id));
    m.addEventListener("keydown", (e) => { const k = (e as KeyboardEvent).key; if (k === "Enter" || k === " ") { e.preventDefault(); openFinding(f.id); } });
    root.appendChild(m);
  }
  const sw = (cls: string, style: string, label: string) => h("span", null, h("span", { class: `sw ${cls}`, style }), label);
  return h("section", { class: "block", id: "coverage", "aria-labelledby": "h-coverage" },
    h("h2", { id: "h-coverage" }, "Evidence coverage", h("small", null, "where the evidence is thin, at a glance")),
    h("div", { class: "panel" },
      h("div", { class: "chart-wrap" }, root),
      h("div", { class: "legend" },
        sw("", "background: var(--lane)", "records per day"),
        sw("", "background: var(--gap-bg); outline: 1px dashed var(--gap)", "evidence gap (labelled with its kind)"),
        sw("", "background: var(--confirmed); border-radius: 50%; width: 10px", "confirmed"),
        sw("", "background: var(--probable); border-radius: 50%; width: 10px", "probable"),
        sw("", "background: var(--possible); border-radius: 50%; width: 10px", "possible detection"),
        sw("", "border-left: 2px dashed var(--inference); width: 2px", "compromise window start"),
        h("span", { class: "muted" }, "Select a marker to open the finding."))));
}

// ----------------------------------------------------------------------------- timeline

const filters = { sources: new Set<string>(), levels: new Set<string>(), labels: new Set<string>(["observed", "inference"]) };

function stepSources(st: Dict): string[] {
  return st.sources && st.sources.length ? st.sources : ["analysis"];
}

function timeline(): HTMLElement {
  const steps: Dict[] = data.timeline.steps || [];
  const allSources = Array.from(new Set(steps.flatMap(stepSources))).sort();
  allSources.forEach((x) => filters.sources.add(x));
  ["confirmed", "probable", "possible", "none"].forEach((l) => filters.levels.add(l));
  const list = h("ol", { class: "steps", "aria-label": "Account timeline" });
  const count = h("span", { class: "muted small", "aria-live": "polite" });
  const chip = (set: Set<string>, value: string, label: string) => {
    const b = h("button", { class: "chip", type: "button", "aria-pressed": "true" }, label);
    b.addEventListener("click", () => {
      if (set.has(value)) set.delete(value); else set.add(value);
      b.setAttribute("aria-pressed", String(set.has(value)));
      draw();
    });
    return b;
  };
  const draw = () => {
    list.replaceChildren();
    let shown = 0;
    for (const st of steps) {
      const lvl = st.level || "none";
      if (!filters.labels.has(st.label) || !filters.levels.has(lvl)) continue;
      if (!stepSources(st).some((x) => filters.sources.has(x))) continue;
      shown++;
      const cls = `step ${st.label}${st.level === "confirmed" ? " lv-c" : st.level === "probable" ? " lv-p" : ""}`;
      const card = h("button", { class: "card", type: "button", "aria-label": `${st.label} at ${fmt(st.ts)}: ${st.title}` },
        h("div", { class: "row1" }, labelBadge(st.label), levelBadge(st.level),
          st.rule_id ? h("span", { class: "muted small mono" }, st.rule_id) : null,
          st.phase && st.phase !== "other" ? h("span", { class: "muted small" }, st.phase.replace(/_/g, " ")) : null),
        h("div", { class: "title" }, st.title),
        st.label === "inference" && st.basis ? h("div", { class: "sub" }, "Rests on: " + st.basis.slice(0, 2).join("; ")
          + (st.basis.length > 2 ? ` and ${st.basis.length - 2} more (open the step)` : "")) : null,
        st.session_link && st.kind !== "interpretation" && st.session_link.method !== "self"
          ? h("div", { class: "sub" }, `Linked to sign-in: ${st.session_link.text}${st.session_link.label === "inference" ? " (inference)" : ""}`) : null);
      card.addEventListener("click", () => openStep(st));
      list.appendChild(h("li", { class: cls, id: `step-${st.id}` },
        h("div", { class: "when" }, h("b", null, st.ts.slice(5, 10)), st.ts.slice(11, 16)),
        h("div", { class: "node", "aria-hidden": "true" }, h("span")),
        card));
    }
    if (!shown) list.appendChild(h("li", { class: "empty" }, "No steps match the filters."));
    count.textContent = `${shown} of ${steps.length} steps`;
  };
  draw();
  const linking = data.timeline.linking || {};
  return h("section", { class: "block", id: "timeline", "aria-labelledby": "h-timeline" },
    h("h2", { id: "h-timeline" }, "Account timeline", h("small", null, `${data.case.user}, times in UTC`)),
    h("div", { class: "panel" },
      h("div", { class: "filters", role: "group", "aria-label": "Timeline filters" },
        h("div", { class: "grp" }, h("span", null, "Statement"), chip(filters.labels, "observed", "Observed facts"), chip(filters.labels, "inference", "Inferences")),
        h("div", { class: "grp" }, h("span", null, "Confidence"), ...["confirmed", "probable", "possible"].map((l) => chip(filters.levels, l, l)), chip(filters.levels, "none", "no level")),
        h("div", { class: "grp" }, h("span", null, "Source"), ...allSources.map((x) => chip(filters.sources, x, x === "analysis" ? "analysis" : short(x)))),
        count),
      list,
      h("p", { class: "small muted", style: "margin:10px 0 0" },
        "Session linking for this account's activity: ",
        Object.entries(linking).map(([k, v]) => `${v} by ${k === "token_id" ? "token identifier" : k === "session_id" ? "session ID" : k === "ip_time" ? "IP and time (inference)" : k === "none" ? "no link possible" : k}`).join(", "),
        ". Links through an identifier recorded in both logs are observed; links by IP address and time are inferences.")));
}

// ----------------------------------------------------------------------------- findings

function evidenceTable(ids: string[], onPick: (id: string) => void): HTMLElement {
  const rows = ids.map((id) => {
    const e = data.events[id];
    if (!e) return h("tr", null, h("td", { colspan: 6, class: "muted" }, `${id} (not embedded)`));
    const raw = e.raw || {};
    const tr = h("tr", { class: "click", tabindex: 0, "aria-label": `Open record ${id}` },
      h("td", { class: "mono" }, fmt(e.ts_utc, true)),
      h("td", null, short(e.source)),
      h("td", null, e.operation || e.action),
      h("td", { class: "mono" }, e.ip),
      h("td", { class: "mono wrap" }, `${e.file}:${e.line_start}`),
      h("td", null, raw.verified === true ? h("span", { class: "verify ok" }, "verified") : raw.verified === false ? h("span", { class: "verify bad" }, "changed") : h("span", { class: "verify na" }, "n/a")));
    tr.addEventListener("click", () => onPick(id));
    tr.addEventListener("keydown", (ev) => { if ((ev as KeyboardEvent).key === "Enter") onPick(id); });
    return tr;
  });
  return h("div", { class: "tbl-wrap" }, h("table", { class: "data" },
    h("thead", null, h("tr", null, ["Time (UTC)", "Source", "Operation", "IP", "File:line", "Raw record"].map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", null, rows)));
}

function findings(): HTMLElement {
  const fs = [...data.findings].sort((a: Dict, b: Dict) => (LEVEL_RANK[b.level] - LEVEL_RANK[a.level]) || (a.first_ts < b.first_ts ? -1 : 1));
  const cards = fs.map((f: Dict) => {
    const open = h("button", { class: "btn no-print", type: "button" }, "Open evidence and raw records");
    open.addEventListener("click", () => openFinding(f.id));
    return h("article", { class: `panel finding lv-${f.level}`, id: `finding-${f.id}` },
      h("h3", null, levelBadge(f.level), f.title, h("span", { class: "muted small mono" }, `${f.id} ${f.rule_id}`)),
      h("div", null, f.summary),
      h("div", { class: "reason" }, h("b", null, "Why this level: "), f.level_reason),
      h("dl", { class: "kv" },
        h("dt", null, "When"), h("dd", null, `${fmt(f.first_ts)} to ${fmt(f.last_ts)} UTC`),
        h("dt", null, "Evidence"), h("dd", null, `${f.event_count} record(s)${f.evidence_truncated ? " (first 200 embedded)" : ""}`),
        h("dt", null, "ATT&CK"), h("dd", null, f.attack.map((a: Dict) => `${a.id} ${a.name}`).join("; ")),
        h("dt", null, "Indicators"), h("dd", { class: "mono small" }, [...f.indicators.ips, ...f.indicators.session_ids.map((x: string) => `session ${x}`)].slice(0, 6).join(", ") || "none")),
      h("p", { class: "why" }, h("b", null, "Why it is suspicious: "), f.why),
      h("p", { class: "why" }, h("b", null, "Known benign explanations: "), f.benign.join("; ")),
      open,
      h("details", { class: "evidence" }, h("summary", null, `Evidence records (${Math.min(f.event_ids.length, 200)})`),
        evidenceTable(f.event_ids.slice(0, 50), (id) => openEvent(id, { kind: "finding", id: f.id }))));
  });
  return h("section", { class: "block", id: "findings", "aria-labelledby": "h-findings" },
    h("h2", { id: "h-findings" }, "Findings", h("small", null, `${fs.length} finding(s), each with the exact records that triggered it`)),
    cards.length ? cards : h("div", { class: "panel muted" }, "No findings."));
}

// ----------------------------------------------------------------------------- gaps and capability

function gaps(): HTMLElement {
  const cov = data.coverage;
  const ref = cov.reference || {};
  const srcRows = (cov.sources || []).map((src: Dict) => h("tr", null,
    h("td", null, h("b", null, short(src.source)), h("div", { class: "muted small" }, src.title)),
    h("td", null, statusPill(src.status)),
    h("td", { class: "mono small" }, src.covers_first ? `${fmt(src.covers_first).slice(0, 10)} to ${fmt(src.covers_last).slice(0, 10)}` : ""),
    h("td", null, src.events.toLocaleString()),
    h("td", null, src.user_events.toLocaleString()),
    h("td", { class: "small" }, src.retention?.summary || ""),
    h("td", { class: "small" }, src.verified ? "verified" : h("span", { class: "warn", title: (src.unverified || []).join("; ") }, "not fully verified"))));
  const gapCards = (cov.gaps || []).map((g: Dict) => h("article", { class: "panel gap" },
    h("h3", null, `${(GAP_LABEL[g.kind] || g.kind).replace(/^./, (c: string) => c.toUpperCase())}: ${g.source_title}`),
    h("p", { style: "margin:4px 0" }, g.statement),
    h("dl", { class: "kv" },
      h("dt", null, "Period"), h("dd", { class: "mono small" }, `${fmt(g.start)} to ${fmt(g.end)} UTC`),
      h("dt", null, "Likely causes"), h("dd", null, h("ul", { style: "margin:0;padding-left:18px" }, g.likely_causes.map((c: string) => h("li", null, c)))),
      h("dt", null, "Checks affected"), h("dd", { class: "mono small" }, (g.affects_rules || []).join(", ") || "none")),
    g.citations?.length ? h("div", { class: "cites" }, "Reference: ", g.citations.map((c: Dict, i: number) => [i ? "; " : "", h("a", { href: c.url, rel: "noreferrer noopener" }, c.url)])) : null,
    g.reference_verified === false ? h("div", { class: "warn" }, "The reference table entry behind this gap is not fully verified.") : null));
  const capRows = (data.capability || []).map((c: Dict) => h("tr", null,
    h("td", { class: "mono" }, c.rule_id), h("td", null, c.title), h("td", null, statusPill(c.status)),
    h("td", null, String(c.findings ?? 0)), h("td", { class: "small" }, (c.reasons || []).join("; "))));
  return h("section", { class: "block", id: "gaps", "aria-labelledby": "h-gaps" },
    h("h2", { id: "h-gaps" }, "Evidence gaps", h("small", null, `reasoned from gap reference table ${ref.version}`)),
    h("div", { class: "panel" },
      h("p", { style: "margin-top:0" }, "Cloud logs depend on licensing, audit configuration and retention, so an absence of records does not show that nothing happened. This section lists what was supplied, what was not, and whether each check could be made at all."),
      h("div", { class: "tbl-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Log source", "Status", "Period covered", "Records", "This account", "Default retention", "Reference"].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", null, srcRows)))),
    gapCards.length ? gapCards : h("div", { class: "panel" }, "No gaps were found in the supplied logs."),
    h("div", { class: "panel" },
      h("h3", { style: "margin-top:0;font-size:15px" }, "Could each check be made with the supplied logs?"),
      h("p", { class: "small muted", style: "margin-top:0" }, "\"Could not be assessed\" means the data was not capable of showing the behaviour. It is never the same as \"nothing found\"."),
      h("div", { class: "tbl-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Rule", "Check", "Status", "Findings", "Reason"].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", null, capRows)))),
    (ref.unverified_entries || []).length ? h("div", { class: "panel small" }, h("b", null, "Unverified reference entries: "), ref.unverified_entries.join(", "),
      ". Their statements are best knowledge, listed for checking in VERIFY.md.") : null);
}

// ----------------------------------------------------------------------------- pivot

function pivot(): HTMLElement {
  const rows = (data.pivot || []).map((p: Dict) => h("tr", null,
    h("td", null, h("b", null, p.account)),
    h("td", null, h("span", { class: `st st-${p.strength === "strong" ? "missing" : p.strength === "medium" ? "partial" : "no_records"}` }, p.strength)),
    h("td", { class: "small" }, p.matches.map((m: Dict) => h("div", null, h("span", { class: "mono" }, `${m.kind} ${m.value.length > 60 ? m.value.slice(0, 60) + "..." : m.value}`), ` x${m.count} (${m.actions.join(", ")})`))),
    h("td", { class: "mono small" }, `${fmt(p.first)} to ${fmt(p.last)}`),
    h("td", null, (() => {
      const id = p.matches[0]?.example_event_ids?.[0];
      if (!id) return "";
      const b = h("button", { class: "btn no-print", type: "button" }, "Example record");
      b.addEventListener("click", () => openEvent(id, null));
      return b;
    })())));
  const basis = data.pivot?.[0]?.basis;
  return h("section", { class: "block", id: "pivot", "aria-labelledby": "h-pivot" },
    h("h2", { id: "h-pivot" }, "Other accounts with the same indicators", h("small", null, "where to look next, not full investigations")),
    h("div", { class: "panel" },
      rows.length ? h("div", { class: "tbl-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Account", "Match strength", "Shared indicators", "Seen (UTC)", ""].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", null, rows))) : h("p", { class: "muted", style: "margin:0" }, "No other account in the supplied logs shares the attacker indicators."),
      basis ? h("p", { class: "small muted", style: "margin:10px 0 0" }, `Indicators taken from ${basis}. Session and token matches are strong, IP and application matches medium, user-agent matches weak.`) : null));
}

// ----------------------------------------------------------------------------- inputs and method

function inputs(): HTMLElement {
  const rows = (data.inputs || []).map((i: Dict) => h("tr", null,
    h("td", { class: "wrap" }, i.path),
    h("td", { class: "mono small wrap" }, i.sha256),
    h("td", null, Number(i.size).toLocaleString()),
    h("td", { class: "small" }, i.parser ? h("span", { title: i.parser_reason }, i.parser) : h("span", { class: "warn" }, "not recognised"), h("div", { class: "muted" }, i.encoding || "")),
    h("td", null, `${i.records_parsed}/${i.records_total}`),
    h("td", null, String((i.records_unrecognised || 0) + (i.records_malformed || 0)))));
  const t = data.totals;
  const reasons = data.unrecognised?.reasons || [];
  return h("section", { class: "block", id: "inputs", "aria-labelledby": "h-inputs" },
    h("h2", { id: "h-inputs" }, "Inputs and integrity"),
    h("div", { class: "panel" },
      h("p", { style: "margin-top:0" }, `Every input was hashed with SHA-256 before parsing and opened read-only. ${t.files} file(s), ${t.records_total} record(s): ${t.records_parsed} parsed, ${t.records_unrecognised} not recognised, ${t.records_malformed} malformed. ${data.linking.duplicates || 0} duplicate record(s) and ${data.linking.corroborating || 0} audit-log copies of sign-ins were linked rather than counted twice.`),
      h("div", { class: "tbl-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["File", "SHA-256", "Bytes", "Parser", "Parsed", "Not parsed"].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", null, rows))),
      reasons.length ? h("div", { style: "margin-top:10px" }, h("b", null, "Records not parsed, by reason: "), reasons.map((r: Dict) => `${r.reason} (${r.count})`).join("; ")) : null,
      h("dl", { class: "kv", style: "margin-top:12px" },
        h("dt", null, "Tool"), h("dd", null, `${data.tool.name} ${data.tool.version}`),
        h("dt", null, "Rule set"), h("dd", null, data.tool.ruleset),
        h("dt", null, "Gap reference table"), h("dd", null, data.tool.reference_table),
        h("dt", null, "Event schema"), h("dd", null, data.tool.schema),
        h("dt", null, "Input folder"), h("dd", { class: "mono small wrap" }, data.case.input_dir))));
}

function method(): HTMLElement {
  return h("section", { class: "block", id: "method", "aria-labelledby": "h-method" },
    h("h2", { id: "h-method" }, "Method and confidence levels"),
    h("div", { class: "panel" },
      h("dl", { class: "kv" },
        h("dt", null, levelBadge("confirmed")), h("dd", null, "The logs record the action, and it is tied to attacker access by an identifier the logs themselves carry (a shared session or token ID, or a session replayed from an impossible location)."),
        h("dt", null, levelBadge("probable")), h("dd", null, "The logs record the action and two or more independent indicators point to the attacker, but the link rests on correlation such as the same unfamiliar IP address rather than a recorded identifier."),
        h("dt", null, levelBadge("possible")), h("dd", null, "A single indicator, or a pattern for which benign explanations remain about as plausible. A lead to review, not a conclusion.")),
      h("p", null, "Detections are rules stored as data; each finding lists the exact records that triggered it, the reason for its level, why the behaviour is suspicious and the known benign explanations. There is no numeric risk score. \"Unusual\" always means not seen for this account in the supplied logs before the compromise window; when the logs do not reach back far enough, the check is reported as not assessable."),
      h("p", { style: "margin-bottom:0" }, "Timeline steps are labelled ", labelBadge("observed"), " when read directly from records, and ", labelBadge("inference"), " when they go beyond the records; inferences state what they rest on.")));
}

// ----------------------------------------------------------------------------- drawer

let drawer: HTMLElement | null = null;
let backdrop: HTMLElement | null = null;

function closeDrawer(): void {
  drawer?.remove();
  backdrop?.remove();
  drawer = backdrop = null;
  history.replaceState(null, "", location.pathname + location.search);
  lastFocus?.focus();
}

function showDrawer(title: Child, body: Child[], hash: string): void {
  if (!drawer) lastFocus = document.activeElement as HTMLElement;
  drawer?.remove();
  backdrop?.remove();
  backdrop = h("div", { class: "backdrop", onclick: closeDrawer });
  const close = h("button", { class: "btn", type: "button", "aria-label": "Close" }, "Close");
  close.addEventListener("click", closeDrawer);
  drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "dr-title" },
    h("header", null, h("h2", { id: "dr-title" }, title), close),
    h("div", { class: "body" }, body));
  document.body.append(backdrop, drawer);
  close.focus();
  history.replaceState(null, "", "#" + hash);
}

function openFinding(id: string): void {
  const f = data.findings.find((x: Dict) => x.id === id);
  if (!f) return;
  const rule = data.rules[f.rule_id] || {};
  const step = (data.timeline.steps || []).find((st: Dict) => st.finding_id === id && st.kind === "finding");
  showDrawer([levelBadge(f.level), " ", f.title], [
    h("p", { style: "margin-top:0" }, f.summary),
    h("p", { class: "small" }, h("b", null, "Why this level: "), f.level_reason),
    h("dl", { class: "kv" },
      h("dt", null, "Finding"), h("dd", { class: "mono" }, `${f.id} (rule ${f.rule_id} v${f.rule_version})`),
      h("dt", null, "When"), h("dd", null, `${fmt(f.first_ts, true)} to ${fmt(f.last_ts, true)} UTC`),
      h("dt", null, "ATT&CK"), h("dd", null, f.attack.map((a: Dict) => `${a.id} ${a.name}`).join("; ")),
      step?.session_link ? h("dt", null, "Session link") : null,
      step?.session_link ? h("dd", null, labelBadge(step.session_link.label), " ", step.session_link.text) : null),
    h("h3", null, "Why it is suspicious"), h("p", null, f.why),
    h("h3", null, "Known benign explanations"), h("ul", null, f.benign.map((b: string) => h("li", null, b))),
    h("h3", null, "Confidence criteria for this rule"),
    h("ul", null, (rule.confidence || []).map((c: Dict) => h("li", null, levelBadge(c.level), " ", c.reason))),
    h("h3", null, `Evidence (${f.event_count} record(s); select one to see the raw record)`),
    evidenceTable(f.event_ids, (eid) => openEvent(eid, { kind: "finding", id: f.id })),
  ], `finding=${id}`);
}

function openStep(st: Dict): void {
  if (st.finding_id && st.kind === "finding") return openFinding(st.finding_id);
  showDrawer([labelBadge(st.label), " ", st.title], [
    h("dl", { class: "kv" },
      h("dt", null, "Time"), h("dd", null, `${fmt(st.ts, true)} UTC`),
      st.level ? h("dt", null, "Confidence") : null, st.level ? h("dd", null, levelBadge(st.level)) : null),
    st.basis ? [h("h3", null, "What this rests on"), h("ul", null, st.basis.map((b: string) => h("li", null, b)))] : null,
    st.session_link ? [h("h3", null, "Session link"), h("p", null, labelBadge(st.session_link.label), " ", st.session_link.text)] : null,
    h("h3", null, "Records"),
    evidenceTable(st.event_ids, (eid) => openEvent(eid, { kind: "step", id: st.id })),
  ], `step=${st.id}`);
}

function openEvent(id: string, back: { kind: string; id: string } | null): void {
  const e = data.events[id];
  if (!e) return;
  const raw = e.raw || {};
  const rawPre = h("pre", { class: "raw", tabindex: 0, "aria-label": "Raw record text" }, raw.available ? raw.text : raw.note);
  let formatted = false;
  const fmtBtn = h("button", { class: "btn", type: "button" }, "Show formatted");
  fmtBtn.addEventListener("click", () => {
    formatted = !formatted;
    if (formatted) {
      try { rawPre.textContent = JSON.stringify(JSON.parse(raw.text), null, 2); } catch { rawPre.textContent = raw.text; }
      fmtBtn.textContent = "Show exact text";
    } else {
      rawPre.textContent = raw.text;
      fmtBtn.textContent = "Show formatted";
    }
  });
  const crumbs = back ? h("div", { class: "crumbs" }, h("button", {
    type: "button", onclick: () => (back.kind === "finding" ? openFinding(back.id) : openStep((data.timeline.steps || []).find((s2: Dict) => s2.id === back.id))),
  }, back.kind === "finding" ? `Back to finding ${back.id}` : "Back to timeline step")) : null;
  const kv = (k: string, v: any) => (v === undefined || v === null || v === "" ? null : [h("dt", null, k), h("dd", { class: "mono small wrap" }, String(v))]);
  const loc = [e.geo_city, e.geo_region, e.geo_country].filter(Boolean).join(", ");
  showDrawer(`${e.operation || e.action} at ${fmt(e.ts_utc, true)} UTC`, [
    crumbs,
    h("dl", { class: "kv" },
      kv("Event", id), kv("Time (UTC)", e.ts_utc), kv("Time as recorded", `${e.ts_original} (${e.ts_note})`),
      kv("Log source", `${short(e.source)} (parser ${e.parser})`), kv("Account", e.actor), kv("Target", e.target),
      kv("Action", `${e.action} (${e.category}) ${e.outcome}`), kv("IP address", e.ip), kv("Location (from the log)", loc),
      kv("Client", [e.client_app, e.user_agent].filter(Boolean).join(" | ")), kv("Application", [e.app_name, e.app_id].filter(Boolean).join(" ")),
      kv("Device", [e.device_os, e.device_browser, e.device_id].filter(Boolean).join(" ")), kv("Session ID", e.session_id),
      kv("Token ID", e.token_id), kv("Record ID", e.record_id), kv("Linked record", e.link_basis)),
    h("h3", null, "Raw record"),
    h("p", { class: "small", style: "margin:0 0 6px" },
      raw.verified === true ? h("span", { class: "verify ok" }, "Re-read now; SHA-256 matches the hash recorded at ingest")
        : raw.verified === false ? h("span", { class: "verify bad" }, "Re-read now; SHA-256 does NOT match: the input changed after ingest")
        : h("span", { class: "verify na" }, raw.note || "not available")),
    h("dl", { class: "kv" },
      kv("File", e.file), kv("Span", `line ${e.line_start} column ${e.col_start} to line ${e.line_end} column ${e.col_end}`),
      kv("Byte offset", e.byte_offset), kv("Record SHA-256", e.raw_sha256), kv("File encoding", raw.encoding)),
    raw.available ? h("div", { style: "margin:6px 0" }, fmtBtn) : null,
    rawPre,
    raw.truncated ? h("p", { class: "small muted" }, "Only the first 20,000 characters are embedded; the full record is in the input file at the span above.") : null,
    h("h3", null, "Normalized details"),
    h("pre", { class: "raw" }, JSON.stringify(e.details, null, 2)),
  ], `event=${id}`);
}

// ----------------------------------------------------------------------------- start

function render(): void {
  const app = document.getElementById("app")!;
  app.replaceChildren(
    header(), nav(),
    h("main", { id: "main" }, h("div", { class: "wrap" }, summary(), coverage(), timeline(), findings(), gaps(), pivot(), inputs(), method())),
    footer());
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && drawer) closeDrawer(); });
  const m = /^#(finding|event|step)=(.+)$/.exec(location.hash);
  if (m) {
    const [, kind, id] = m;
    if (kind === "finding") openFinding(decodeURIComponent(id));
    else if (kind === "event") openEvent(decodeURIComponent(id), null);
    else {
      const st = (data.timeline.steps || []).find((x: Dict) => x.id === decodeURIComponent(id));
      if (st) openStep(st);
    }
  }
  window.addEventListener("beforeprint", () => document.querySelectorAll("details.evidence").forEach((d) => d.setAttribute("open", "")));
}

async function main(): Promise<void> {
  const forced = new URLSearchParams(location.search).get("theme");
  applyTheme(forced === "light" || forced === "dark" ? forced : storedTheme());
  const text = (document.getElementById("tt-data")?.textContent || "").trim();
  if (text.startsWith("__TT_")) {
    if (import.meta.env.DEV) {
      data = await (await fetch("./sample-report.json")).json();
    } else {
      document.getElementById("app")!.textContent = "This is the TenantTrace report template; it holds no case data.";
      return;
    }
  } else {
    data = JSON.parse(text);
  }
  document.title = `TenantTrace report: ${data.case.user}`;
  render();
}

void main();
void LEVELS;
