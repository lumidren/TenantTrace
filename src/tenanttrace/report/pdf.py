"""PDF version of the report, rendered with fpdf2 (pure Python, no system libraries).

The PDF carries the same findings, timeline, gaps, pivot and input record as the HTML and JSON,
laid out for printing and filing. Core PDF fonts cover Latin-1 only, so other characters are
transliterated or replaced; the JSON export keeps the exact text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

_TRANS = str.maketrans({
    "–": "-", "—": "-", "‘": "'", "’": "'", "“": '"', "”": '"', "…": "...",
    "→": "->", "•": "*", " ": " ", "≤": "<=", "≥": ">=", "−": "-",
})
PDF_EVIDENCE_ROWS = 15
SOURCE_SHORT = {
    "entra_signin_interactive": "Entra interactive", "entra_signin_noninteractive": "Entra non-interactive",
    "entra_audit": "Entra audit", "ual_azuread_logon": "UAL sign-in copy", "ual_azuread": "UAL directory",
    "ual_exchange_admin": "UAL Exchange admin", "ual_mailbox_items": "UAL mailbox", "ual_sharepoint": "UAL SharePoint",
}
LEVEL_FILL = {"confirmed": (176, 32, 46), "probable": (196, 105, 0), "possible": (94, 105, 120)}


def t(s: Any) -> str:
    s = "" if s is None else str(s)
    return s.translate(_TRANS).encode("latin-1", "replace").decode("latin-1")


def ts(s: str) -> str:
    return (s or "")[:19].replace("T", " ")


class ReportPDF(FPDF):
    def __init__(self, data: dict[str, Any]):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.data = data
        self.set_auto_page_break(auto=True, margin=16)
        self.set_margins(14, 14, 14)
        self.set_title(t(f"TenantTrace report: {data['case']['user']}"))
        self.set_creator(t(f"{data['tool']['name']} {data['tool']['version']}"))

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(110, 110, 110)
        self.cell(0, 5, t(f"TenantTrace investigation report - {self.data['case']['user']}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def footer(self) -> None:
        self.set_y(-11)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(110, 110, 110)
        tool = self.data["tool"]
        self.cell(0, 5, t(f"{tool['name']} {tool['version']} | rule set {tool.get('ruleset', '')} | reference table "
                          f"{tool.get('reference_table', '')} | page {self.page_no()}/{{nb}}"), align="C")
        self.set_text_color(0, 0, 0)

    # helpers
    def h1(self, text: str) -> None:
        self.ln(2)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(20, 45, 80)
        self.multi_cell(0, 7, t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(20, 45, 80)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def h2(self, text: str) -> None:
        self.ln(1)
        self.set_font("Helvetica", "B", 10.5)
        self.multi_cell(0, 5.5, t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(self, text: str, size: float = 9, style: str = "") -> None:
        self.set_font("Helvetica", style, size)
        self.multi_cell(0, 4.6, t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def bullets(self, items: list[str], size: float = 9) -> None:
        self.set_font("Helvetica", "", size)
        for it in items:
            x = self.get_x()
            self.cell(4, 4.6, "-")
            self.multi_cell(0, 4.6, t(it), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_x(x)

    def badge(self, level: str) -> None:
        r, g, b = LEVEL_FILL.get(level, (90, 90, 90))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 7.5)
        self.cell(self.get_string_width(level.upper()) + 4, 4.6, t(level.upper()), fill=True)
        self.set_text_color(0, 0, 0)

    def table(self, headers: list[str], rows: list[list[str]], widths: list[float], size: float = 7.5) -> None:
        self.set_font("Helvetica", "", size)
        with super().table(col_widths=widths, text_align="LEFT", line_height=3.8, first_row_as_headings=True,
                           headings_style=_heading_style(), borders_layout="HORIZONTAL_LINES") as tbl:
            row = tbl.row()
            for h in headers:
                row.cell(t(h))
            for r in rows:
                row = tbl.row()
                for c in r:
                    row.cell(t(c))
        self.ln(2)


def _heading_style():
    from fpdf.fonts import FontFace

    return FontFace(emphasis="BOLD", fill_color=(232, 237, 245))


def render_pdf(data: dict[str, Any], path: Path) -> Path:
    pdf = ReportPDF(data)
    pdf.alias_nb_pages()
    pdf.add_page()
    case = data["case"]
    tool = data["tool"]
    s = data["summary"]

    # title block
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(20, 45, 80)
    pdf.multi_cell(0, 10, "Account compromise investigation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)
    win = case.get("window") or {}
    for k, v in (("Account", case["user"]),
                 ("Case period (UTC)", f"{ts(case['case_start'])} to {ts(case['case_end'])}"),
                 ("Collected", f"{ts(case['collected_at'])} ({case['collected_at_basis']})"),
                 ("Compromise window", f"from {ts(win.get('start', ''))} ({win.get('method', '')}: {win.get('basis', '')})"),
                 ("Generated", ts(data["generated_utc"])),
                 ("Tool", f"{tool['name']} {tool['version']}; rule set {tool.get('ruleset')}; reference table "
                          f"{tool.get('reference_table')}; schema {tool.get('schema')}")):
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(38, 5, t(k))
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, t(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.h1("1. Executive summary")
    pdf.para(s["headline"], 10.5, "B")
    pdf.ln(1)
    if s["facts"]:
        pdf.h2("What the evidence shows")
        pdf.bullets(s["facts"])
    pdf.h2("What the evidence cannot show")
    pdf.bullets(s["limits"] or ["No evidence gaps were found in the supplied logs."])
    if s["next_steps"]:
        pdf.h2("Where to look next")
        pdf.bullets(s["next_steps"])

    pdf.h1("2. Timeline")
    pdf.para("Each step is either an observed fact read from the listed records, or an inference that states what it "
             "rests on. Times are UTC.", 8.5)
    rows = []
    for st in data["timeline"].get("steps", []):
        label = "Observed" if st["label"] == "observed" else "Inference"
        detail = st["title"]
        if st["label"] == "inference" and st.get("basis"):
            detail += " | Basis: " + "; ".join(st["basis"])
        link = (st.get("session_link") or {}).get("text")
        if link and st["kind"] != "interpretation":
            detail += " | Link: " + link
        rows.append([ts(st["ts"]), label, (st.get("level") or "").upper(), detail])
    pdf.table(["Time (UTC)", "Label", "Confidence", "Step"], rows, [26, 17, 18, 121])

    pdf.h1("3. Findings")
    events = data["events"]
    for f in data["findings"]:
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.cell(0, 5.5, t(f"{f['id']}  {f['rule_id']}  {f['title']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.badge(f["level"])
        pdf.set_font("Helvetica", "", 8.5)
        pdf.multi_cell(0, 4.6, t(f"  {f['level_reason']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.para(f["summary"], 8.5)
        pdf.para("ATT&CK: " + "; ".join(f"{a['id']} {a['name']}" for a in f["attack"]), 8)
        pdf.para("Why it matters: " + f["why"], 8)
        pdf.para("Benign explanations: " + "; ".join(f["benign"]), 8)
        rows = []
        for eid in f["event_ids"][:PDF_EVIDENCE_ROWS]:
            e = events.get(eid, {})
            raw = e.get("raw", {})
            ver = "yes" if raw.get("verified") else ("NO" if raw.get("verified") is False else "n/a")
            fname = (e.get("file", "") or "").replace("\\", "/").rsplit("/", 1)[-1]
            rows.append([eid, ts(e.get("ts_utc", "")), SOURCE_SHORT.get(e.get("source", ""), e.get("source", "")),
                         e.get("operation", ""), e.get("ip", ""), f"{fname}:{e.get('line_start', '')}", ver])
        if f["event_count"] > PDF_EVIDENCE_ROWS:
            rows.append(["", "", "", f"+{f['event_count'] - PDF_EVIDENCE_ROWS} more", "", "in the HTML and JSON", ""])
        pdf.table(["Event", "Time (UTC)", "Source", "Operation", "IP", "File:line", "Hash ok"], rows,
                  [34, 25, 25, 25, 22, 39, 12], size=6.3)

    pdf.h1("4. Evidence coverage and gaps")
    cov = data["coverage"]
    rows = []
    for src in cov.get("sources") or []:
        rows.append([src["source"], src["status"].replace("_", " "),
                     f"{ts(src.get('covers_first', ''))[:10]} - {ts(src.get('covers_last', ''))[:10]}",
                     str(src["events"]), str(src["user_events"]), "yes" if src["verified"] else "NO"])
    pdf.table(["Source", "Status", "Period covered", "Records", "Account", "Ref. verified"], rows,
              [52, 26, 44, 20, 20, 20])
    gaps = cov.get("gaps") or []
    if not gaps:
        pdf.para("No gaps were found in the supplied logs.", 9)
    for g in gaps:
        pdf.h2(f"{g['kind'].replace('_', ' ').capitalize()}: {g['source_title']}")
        pdf.para(g["statement"], 8.5)
        pdf.para("Likely causes: " + "; ".join(g["likely_causes"]), 8)
        if g.get("affects_rules"):
            pdf.para("Affects: " + ", ".join(g["affects_rules"]), 8)
        if g.get("citations"):
            pdf.para("Sources: " + "; ".join(c["url"] for c in g["citations"]), 7.5)
        if not g.get("reference_verified", True):
            pdf.para("Note: the reference entry behind this gap is not fully verified.", 7.5, "I")
    pdf.h2("Could each check be made with the supplied logs?")
    rows = [[c["rule_id"], c["title"], c["status"].replace("_", " "), str(c.get("findings", 0)),
             "; ".join(c["reasons"])] for c in data["capability"]]
    pdf.table(["Rule", "Check", "Status", "Findings", "Reason"], rows, [22, 52, 22, 15, 71], size=6.8)

    pdf.h1("5. Other accounts with the same indicators")
    if not data["pivot"]:
        pdf.para("No other account in the supplied logs shares the attacker indicators.", 9)
    rows = []
    for p in data["pivot"]:
        rows.append([p["account"], p["strength"], "; ".join(f"{m['kind']} {m['value'][:48]} x{m['count']}"
                                                             for m in p["matches"]), ts(p["first"])])
    if rows:
        pdf.table(["Account", "Strength", "Matching indicators", "First seen"], rows, [55, 18, 82, 27])

    pdf.h1("6. Inputs and integrity")
    rows = [[i["path"], i["sha256"], str(i["size"]), i.get("parser") or "not recognised",
             f"{i.get('records_parsed', 0)}/{i.get('records_total', 0)}",
             str(i.get("records_unrecognised", 0) + i.get("records_malformed", 0))] for i in data["inputs"]]
    pdf.table(["File", "SHA-256", "Bytes", "Parser", "Parsed", "Not parsed"], rows, [45, 60, 17, 30, 15, 15], size=6.3)
    tot = data["totals"]
    pdf.para(f"{tot.get('files', 0)} file(s), {tot.get('records_total', 0)} record(s), {tot.get('records_parsed', 0)} "
             f"parsed, {tot.get('records_unrecognised', 0)} unrecognised, {tot.get('records_malformed', 0)} malformed; "
             f"{data['linking'].get('duplicates', 0)} duplicate(s) and {data['linking'].get('corroborating', 0)} "
             "audit-log copies of sign-ins linked rather than counted twice.", 8.5)
    ref = cov.get("reference") or {}
    pdf.para(f"Gap reference table {ref.get('version', '')}. Unverified entries: "
             f"{', '.join(ref.get('unverified_entries', [])) or 'none'}.", 8.5)
    path = Path(path)
    pdf.output(str(path))
    return path
