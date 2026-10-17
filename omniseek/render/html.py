# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The self-contained HTML dossier.

One file, no external requests: inline CSS and a small script allowed by a
Content-Security-Policy hash. Every value from the findings is HTML-escaped, so
a hostile finding title or code line renders as text. Without JavaScript all
findings are still shown; the script adds lens tabs, severity filters, search
and expand/collapse.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re

from .._version import __version__
from ..model import LENSES, SEVERITIES
from . import first_span, grounding_label, grounding_of, location

SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
GROUNDING_GLYPHS = {"good": "✓", "warning": "◐", "critical": "✕", "unknown": "–"}
CITATION_STATES = {
    "verified": "good", "drifted": "warning", "unanchored": "warning", "hallucinated": "critical", "invalid": "critical",
}

CSS = """
:root{color-scheme:dark;--bg:#121211;--surface:#1a1a19;--surface-2:#232321;--border:#33332f;
--text:#f0efec;--text-2:#c3c2b7;--muted:#9a998f;--accent:#3987e5;
--critical:#d03b3b;--serious:#ec835a;--warning:#fab219;--good:#0ca30c;--low:#3987e5;--info:#8f8e88;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans)}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 64px}
header.top{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-end;justify-content:space-between;margin-bottom:22px}
.brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--text-2)}
h1{margin:4px 0 2px;font-size:28px;line-height:1.2}
.meta{color:var(--text-2);font-size:13px;display:flex;flex-wrap:wrap;gap:4px 14px}
.meta code{font-family:var(--mono);font-size:12px;color:var(--text)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:0 0 16px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.tile .label{color:var(--text-2);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.tile .value{font-size:30px;font-weight:650;line-height:1.15;margin-top:4px;font-variant-numeric:tabular-nums}
.tile .sub{color:var(--muted);font-size:12.5px;margin-top:2px}
.dists{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-bottom:22px}
.dist{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.dist h2{font-size:13px;margin:0 0 10px;color:var(--text-2);font-weight:600;text-transform:uppercase;letter-spacing:.08em}
.bar-row{display:grid;grid-template-columns:96px 1fr 36px;align-items:center;gap:10px;margin:7px 0;font-size:13.5px}
.bar-track{display:block;height:10px;background:var(--surface-2);border-radius:4px;overflow:hidden}
.bar{display:block;height:100%;border-radius:0 4px 4px 0;min-width:0}
.bar-row .n{text-align:right;font-variant-numeric:tabular-nums;color:var(--text)}
.controls{position:sticky;top:0;z-index:5;background:linear-gradient(var(--bg) 85%,transparent);padding:10px 0 12px;
display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.tabs{display:flex;flex-wrap:wrap;gap:6px}
button{font:inherit;cursor:pointer}
.tab,.chip,.tool{background:var(--surface);color:var(--text-2);border:1px solid var(--border);border-radius:999px;
padding:6px 12px;font-size:13px}
.tab[aria-selected=true]{background:var(--text);color:var(--bg);border-color:var(--text)}
.chip[aria-pressed=false]{opacity:.45;text-decoration:line-through}
.tab:focus-visible,.chip:focus-visible,.tool:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.search{flex:1 1 220px;min-width:180px;background:var(--surface);color:var(--text);border:1px solid var(--border);
border-radius:999px;padding:7px 14px;font:inherit;font-size:13.5px}
.count{color:var(--muted);font-size:13px;margin-left:auto}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin:10px 0}
.finding[hidden]{display:none}
.row{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center}
.badge{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:999px;
padding:2px 10px;font-size:12px;color:var(--text);background:var(--surface-2);white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.sev-critical .dot,.dot.critical{background:var(--critical)}.sev-high .dot{background:var(--serious)}
.sev-medium .dot,.dot.warning{background:var(--warning)}.sev-low .dot{background:var(--low)}
.sev-info .dot,.dot.unknown{background:var(--info)}.dot.good{background:var(--good)}
.glyph{font-weight:700}
.ground.good{border-color:color-mix(in srgb,var(--good) 55%,var(--border))}
.ground.warning{border-color:color-mix(in srgb,var(--warning) 55%,var(--border))}
.ground.critical{border-color:color-mix(in srgb,var(--critical) 60%,var(--border))}
.rid{font-family:var(--mono);font-size:12px;color:var(--muted)}
.finding h3{margin:10px 0 4px;font-size:17px;line-height:1.35}
.loc{font-family:var(--mono);font-size:12.5px;color:var(--text-2);word-break:break-all}
.desc{margin:8px 0 6px;color:var(--text)}
.desc code{font-family:var(--mono);font-size:.9em;background:var(--surface-2);border-radius:4px;padding:1px 5px}
.fix{margin:6px 0 2px}
.fix h4,.drawer summary{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-2);margin:10px 0 4px}
.fix ol{margin:4px 0 0;padding-left:22px}
.fix li{margin:2px 0}
.drawer{margin-top:10px;border-top:1px solid var(--border);padding-top:6px}
.drawer summary{cursor:pointer;list-style:none;display:flex;gap:8px;align-items:center;margin:4px 0}
.drawer summary::-webkit-details-marker{display:none}
.drawer summary::before{content:"▸";color:var(--text-2);transition:transform .15s}
.drawer[open] summary::before{transform:rotate(90deg)}
.cite{margin:10px 0 4px}
.cite-head{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font-size:13px}
.cite-head .loc{color:var(--text)}
.reason{color:var(--muted);font-size:12.5px}
pre.code{margin:6px 0 0;background:#0e0e0d;border:1px solid var(--border);border-radius:8px;padding:8px 0;
overflow-x:auto;font:12.5px/1.5 var(--mono)}
pre.code span.l{display:block;padding:0 12px 0 0;white-space:pre}
pre.code span.n{display:inline-block;min-width:4.2em;padding:0 12px 0 10px;text-align:right;color:var(--muted);
user-select:none;border-right:1px solid var(--border);margin-right:12px}
.absent{font-family:var(--mono);font-size:12.5px;color:var(--text-2)}
.empty{background:var(--surface);border:1px dashed var(--border);border-radius:12px;padding:28px;text-align:center;color:var(--text-2)}
footer{margin-top:36px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--border);padding-top:14px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
@media (max-width:640px){.bar-row{grid-template-columns:80px 1fr 30px}h1{font-size:23px}}
@media print{.controls{display:none}body{background:#fff;color:#000}.finding,.tile,.dist{border-color:#bbb;background:#fff}}
"""

SCRIPT = """(function(){
var cards=[].slice.call(document.querySelectorAll('.finding'));
var tabs=[].slice.call(document.querySelectorAll('.tab'));
var chips=[].slice.call(document.querySelectorAll('.chip'));
var search=document.getElementById('q');
var count=document.getElementById('shown');
var state={lens:'all',sev:{},q:''};
chips.forEach(function(c){state.sev[c.dataset.sev]=true;});
function apply(){
  var shown=0;
  cards.forEach(function(card){
    var ok=(state.lens==='all'||card.dataset.lens===state.lens)&&state.sev[card.dataset.sev]!==false&&
      (!state.q||card.dataset.text.indexOf(state.q)!==-1);
    card.hidden=!ok; if(ok){shown++;}
  });
  if(count){count.textContent=shown+' of '+cards.length+' findings shown';}
}
tabs.forEach(function(tab){tab.addEventListener('click',function(){
  tabs.forEach(function(t){t.setAttribute('aria-selected',t===tab?'true':'false');});
  state.lens=tab.dataset.lens; apply();
});});
chips.forEach(function(chip){chip.addEventListener('click',function(){
  var on=chip.getAttribute('aria-pressed')!=='true';
  chip.setAttribute('aria-pressed',on?'true':'false'); state.sev[chip.dataset.sev]=on; apply();
});});
if(search){search.addEventListener('input',function(){state.q=search.value.trim().toLowerCase(); apply();});}
function setAll(open){document.querySelectorAll('.drawer').forEach(function(d){
  if(!d.closest('.finding').hidden){d.open=open;}
});}
var ex=document.getElementById('expand'),co=document.getElementById('collapse');
if(ex){ex.addEventListener('click',function(){setAll(true);});}
if(co){co.addEventListener('click',function(){setAll(false);});}
apply();
})();"""


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _prose(value: object) -> str:
    """Escaped text with `code` spans rendered as <code>."""
    return re.sub(r"`([^`\n]+)`", r"<code>\1</code>", _e(value))


def _badge(classes: str, text: str, glyph: str = "", dot: str = "", title: str = "") -> str:
    title_attr = f' title="{_e(title)}"' if title else ""
    dot_html = f'<span class="dot {dot}" aria-hidden="true"></span>' if dot is not None else ""
    glyph_html = f'<span class="glyph" aria-hidden="true">{glyph}</span>' if glyph else ""
    return f'<span class="badge {classes}"{title_attr}>{dot_html}{glyph_html}{_e(text)}</span>'


def _severity_badge(severity: str) -> str:
    return _badge(f"sev-{_e(severity)}", SEVERITY_LABELS.get(severity, severity), title="Severity")


def _grounding_badge(score: float | None, title: str = "Citation grounding score") -> str:
    state, label = grounding_label(score)
    return _badge(f"ground {state}", label, GROUNDING_GLYPHS[state], dot=state, title=title)


def _code(rows: list[tuple[int | None, str]]) -> str:
    body = "".join(
        f'<span class="l"><span class="n">{"" if n is None else n}</span>{_e(text)}</span>' for n, text in rows
    )
    return f'<pre class="code"><code>{body}</code></pre>'


def _citation(index: int, citation: dict, check: dict | None) -> str:
    parts = ['<div class="cite">', '<div class="cite-head">']
    if check:
        state = CITATION_STATES.get(check.get("status"), "unknown")
        parts.append(_badge(f"ground {state}", check.get("status", ""), GROUNDING_GLYPHS[state], dot=state,
                            title="Citation check"))
    else:
        parts.append(_badge("ground unknown", "not verified", GROUNDING_GLYPHS["unknown"], dot="unknown"))
    if citation.get("kind") == "absence":
        targets = (citation.get("paths") or []) + (citation.get("globs") or [])
        parts.append(f'<span class="loc">absence of {_e(", ".join(targets))}</span>')
    else:
        parts.append(f'<span class="loc">{_e(location(citation))}</span>')
        if citation.get("symbol"):
            parts.append(f'<span class="rid">symbol {_e(citation["symbol"])}</span>')
    parts.append("</div>")
    if check and check.get("reason"):
        reason = check["reason"]
        if check.get("found"):
            reason += " (" + ", ".join(check["found"][:3]) + ")"
        parts.append(f'<div class="reason">{_e(reason)}</div>')
    if citation.get("kind") != "absence":
        excerpt = (check or {}).get("excerpt")
        if excerpt:
            parts.append(_code([(row.get("line"), row.get("text", "")) for row in excerpt]))
        status = (check or {}).get("status")
        if citation.get("snippet") and (not excerpt or status != "verified"):
            if status and status != "verified":
                label = "Quoted by the finding (not found at these lines):" if status != "unanchored" else "Quoted:"
                parts.append(f'<div class="reason">{_e(label)}</div>')
            parts.append(_code([(citation.get("start_line") if isinstance(citation.get("start_line"), int) else None,
                                 citation["snippet"])]))
    parts.append("</div>")
    return "".join(parts)


def _finding(finding: dict) -> str:
    severity = finding.get("severity", "info")
    lens = finding.get("lens", "")
    score = grounding_of(finding)
    checks = {c.get("index"): c for c in (finding.get("verification") or {}).get("citations", [])}
    citations = finding.get("citations", [])
    search_text = " ".join(
        str(x) for x in (finding.get("title"), finding.get("description"), finding.get("rule_id"), lens, severity,
                         location(first_span(finding)), finding.get("id"))
    ).lower()
    parts = [
        f'<article class="finding" id="{_e(finding.get("id"))}" data-lens="{_e(lens)}" data-sev="{_e(severity)}" '
        f'data-text="{_e(search_text)}">',
        '<div class="row">',
        _severity_badge(severity),
        _badge("lens", lens.capitalize(), dot=None),
        _grounding_badge(score),
        f'<span class="rid">{_e(finding.get("rule_id"))} · {_e(finding.get("id"))} · {_e(finding.get("source", ""))}'
        f' · confidence {_e(finding.get("confidence", ""))}</span>',
        "</div>",
        f'<h3>{_e(finding.get("title"))}</h3>',
        f'<div class="loc">{_e(location(first_span(finding)))}</div>',
    ]
    if finding.get("description"):
        parts.append(f'<p class="desc">{_prose(finding["description"])}</p>')
    if finding.get("remediation"):
        steps = "".join(f"<li>{_e(step)}</li>" for step in finding["remediation"])
        parts.append(f'<div class="fix"><h4>Remediation</h4><ol>{steps}</ol></div>')
    if citations:
        verdict = (finding.get("verification") or {}).get("status", "not verified")
        is_open = " open" if verdict not in ("grounded", "not verified") else ""
        verdict = verdict.replace("_", " ")
        parts.append(
            f'<details class="drawer"{is_open}><summary>Evidence · {len(citations)} citation{"s" if len(citations) != 1 else ""}'
            f" · {_e(verdict)}</summary>"
            + "".join(_citation(i, c, checks.get(i)) for i, c in enumerate(citations))
            + "</details>"
        )
    parts.append("</article>")
    return "".join(parts)


def _bars(title: str, rows: list[tuple[str, int, str]]) -> str:
    peak = max([n for _, n, _ in rows] + [1])
    body = "".join(
        f'<div class="bar-row" title="{_e(label)}: {n}"><span>{_e(label)}</span>'
        f'<span class="bar-track"><span class="bar" style="width:{n / peak * 100:.1f}%;background:var({color})"></span></span>'
        f'<span class="n">{n}</span></div>'
        for label, n, color in rows
    )
    return f'<section class="dist" aria-label="{_e(title)}"><h2>{_e(title)}</h2>{body}</section>'


def render_html(document: dict) -> str:
    findings = document.get("findings", [])
    repo = document.get("repo", {})
    analyzer = document.get("analyzer", {})
    verification = document.get("verification") or {}
    by_sev = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    by_lens = {lens: sum(1 for f in findings if f.get("lens") == lens) for lens in LENSES}
    sev_colors = {"critical": "--critical", "high": "--serious", "medium": "--warning", "low": "--low", "info": "--info"}
    score = verification.get("grounding_score") if isinstance(verification.get("grounding_score"), (int, float)) else None
    state, label = grounding_label(score)
    name = repo.get("name") or "repository"

    meta = [f"<span>{_e(document.get('generated_at', ''))}</span>"]
    if repo.get("commit"):
        meta.append(f"<span>commit <code>{_e(repo['commit'][:12])}</code></span>")
    mode = analyzer.get("mode", "heuristic") + (f" · {analyzer['model']}" if analyzer.get("model") else "")
    meta.append(f"<span>mode <code>{_e(mode)}</code></span>")
    if analyzer.get("lenses"):
        meta.append(f"<span>lenses {_e(', '.join(analyzer['lenses']))}</span>")

    kpis = [
        ("Findings", str(len(findings)), f"{by_sev['critical']} critical · {by_sev['high']} high · {by_sev['medium']} medium"),
        ("Critical + high", str(by_sev["critical"] + by_sev["high"]), "fix these first"),
        (
            "Grounding",
            "–" if score is None else f"{score:.2f}",
            f"{GROUNDING_GLYPHS[state]} {label}" + (
                f" · {verification.get('citations_by_status', {}).get('verified', 0)} of "
                f"{verification.get('citations_total', 0)} citations verified" if score is not None else ""
            ),
        ),
        ("Files scanned", str(repo.get("files_scanned", "–")), ", ".join(list((repo.get("languages") or {}))[:4])),
    ]
    tiles = "".join(
        f'<div class="tile"><div class="label">{_e(k)}</div><div class="value">{_e(v)}</div>'
        f'<div class="sub">{_e(s)}</div></div>'
        for k, v, s in kpis
    )
    tabs = [f'<button class="tab" role="tab" aria-selected="true" data-lens="all">All ({len(findings)})</button>']
    tabs += [
        f'<button class="tab" role="tab" aria-selected="false" data-lens="{lens}">{lens.capitalize()} ({by_lens[lens]})</button>'
        for lens in LENSES
    ]
    chips = [
        f'<button class="chip sev-{s}" aria-pressed="true" data-sev="{s}">'
        f'<span class="dot" aria-hidden="true"></span> {SEVERITY_LABELS[s]} ({by_sev[s]})</button>'
        for s in SEVERITIES
        if by_sev[s]
    ]
    cards = "".join(_finding(f) for f in findings) or (
        '<div class="empty">No findings for the selected lenses. Nothing to fix here.</div>'
    )
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode()
    # Built only from constants and a base64 digest, so it needs no escaping inside the attribute.
    csp = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; img-src data:"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="generator" content="OmniSeek {_e(__version__)}">
<title>OmniSeek dossier · {_e(name)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="top">
<div><div class="brand">OmniSeek dossier</div><h1>{_e(name)}</h1><div class="meta">{"".join(meta)}</div></div>
</header>
<section class="kpis" aria-label="Summary">{tiles}</section>
<div class="dists">
{_bars("Findings by severity", [(SEVERITY_LABELS[s], by_sev[s], sev_colors[s]) for s in SEVERITIES])}
{_bars("Findings by lens", [(lens.capitalize(), by_lens[lens], "--accent") for lens in LENSES])}
</div>
<nav class="controls" aria-label="Filter findings">
<div class="tabs" role="tablist" aria-label="Lens">{"".join(tabs)}</div>
<div class="tabs" aria-label="Severity">{"".join(chips)}</div>
<label class="sr" for="q">Search findings</label>
<input id="q" class="search" type="search" placeholder="Search title, file, rule…" autocomplete="off">
<button class="tool" id="expand" type="button">Expand evidence</button>
<button class="tool" id="collapse" type="button">Collapse</button>
<span class="count" id="shown" aria-live="polite">{len(findings)} findings</span>
</nav>
<main>{cards}</main>
<footer>Generated by OmniSeek {_e(__version__)} (Apache-2.0). Findings come from deterministic heuristics
and, when configured, your own model; the grounding badge shows whether each cited line was found in the
repository, not whether the finding is right. Check the evidence before acting.</footer>
</div>
<script>{SCRIPT}</script>
</body>
</html>
"""
