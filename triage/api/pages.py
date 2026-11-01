"""Server-rendered analyst pages, styled as an evidence docket.

Log text is hostile: every dynamic value goes through escape(). The only script is the
accept/reject form, which reads its alert id from a data attribute, never from markup.
"""

from html import escape
from typing import Any

REPO = "https://github.com/varunb1996/Probative-AI"
FONTS = ("https://fonts.googleapis.com/css2?family=Gloock&family=Familjen+Grotesk:wght@400;600"
         "&family=Martian+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,600;"
         "1,6..72,400&display=swap")
ROUTE_LABEL = {"escalate": "Escalated", "investigate": "Investigate", "suggest_close": "Suggest close",
               "auto_close": "Auto-closed", "scored_only": "Scored only"}
_SKIPPED = "AI not run"
CHECK_LABEL = {"schema": "Output matches the contract", "citation_grounding": "Every citation exists in the evidence",
               "hard_override": "No intel hit or critical host", "baseline_disagreement": "Agrees with the evidence score",
               "injection_tripwire": "No instructions hidden in the logs",
               "calibrated_confidence": "Confident enough for this rule type",
               "trigger_anchoring": "Cites the triggering event"}

_STYLE = """
:root {
  --paper: #f2eadb; --paper-deep: #e7dcc6; --ink: #1d1813; --ink-soft: #5b5145; --rule: rgba(29,24,19,.09);
  --margin: #9b2a1f; --escalate: #8f1d14; --investigate: #9a5b12; --close: #2c5b4e;
  --card: rgba(255,251,242,.72); --shadow: 0 1px 0 rgba(29,24,19,.06), 0 12px 30px -18px rgba(29,24,19,.35);
  --display: "Gloock", "Didot", serif; --body: "Newsreader", "Georgia", serif;
  --label: "Familjen Grotesk", "Helvetica Neue", sans-serif; --mono: "Martian Mono", "Consolas", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #17130f; --paper-deep: #211b15; --ink: #efe6d6; --ink-soft: #a89a86; --rule: rgba(239,230,214,.07);
    --margin: #c9473a; --escalate: #e0604f; --investigate: #e0a24a; --close: #6fb7a1;
    --card: rgba(36,29,22,.78); --shadow: 0 1px 0 rgba(0,0,0,.4), 0 16px 34px -20px rgba(0,0,0,.8);
  }
}
* { box-sizing: border-box; }
html { background: var(--paper); }
body {
  margin: 0; color: var(--ink); font: 17px/1.55 var(--body); font-optical-sizing: auto;
  background:
    linear-gradient(90deg, transparent 0 calc(var(--gutter) - 4px), var(--margin) calc(var(--gutter) - 4px) calc(var(--gutter) - 3px),
                    transparent calc(var(--gutter) - 3px) calc(var(--gutter) + 1px), var(--margin) calc(var(--gutter) + 1px) calc(var(--gutter) + 2px), transparent 0),
    repeating-linear-gradient(180deg, transparent 0 31px, var(--rule) 31px 32px),
    radial-gradient(120% 80% at 85% -10%, var(--paper-deep), transparent 60%),
    var(--paper);
  background-attachment: fixed; min-height: 100vh; --gutter: 56px;
}
a { color: inherit; text-decoration-color: var(--margin); text-underline-offset: 3px; }
main { max-width: 1080px; margin: 0 auto; padding: 40px 24px 80px calc(var(--gutter) + 32px); }
.kicker { font: 600 12px/1 var(--label); letter-spacing: .22em; text-transform: uppercase; color: var(--margin); }
h1 { font: 400 clamp(44px, 7vw, 86px)/.92 var(--display); letter-spacing: -.02em; margin: 14px 0 18px; }
h1 em { font-style: normal; color: var(--margin); }
h2 { font: 400 30px/1.1 var(--display); margin: 56px 0 6px; display: flex; align-items: baseline; gap: 14px; }
h2 .count { font: 500 13px var(--mono); color: var(--ink-soft); }
.lede { max-width: 62ch; color: var(--ink-soft); font-size: 18px; margin: 0; }
.lede code, .mono { font-family: var(--mono); font-size: .78em; }
.procedure { margin: 26px 0 0; font: 400 12px/1.9 var(--mono); color: var(--ink-soft); letter-spacing: .02em; }
.procedure b { color: var(--ink); font-weight: 500; }
.procedure .model { color: var(--margin); }

.tally { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0; margin-top: 40px;
         border-top: 2px solid var(--ink); border-bottom: 1px solid var(--ink); }
.tally div { padding: 14px 18px 16px 0; }
.tally div + div { padding-left: 18px; border-left: 1px solid var(--rule); }
.tally b { display: block; font: 400 54px/1 var(--display); }
.tally span { font: 600 11px var(--label); letter-spacing: .18em; text-transform: uppercase; color: var(--ink-soft); }
.tally .escalate b { color: var(--escalate); } .tally .investigate b { color: var(--investigate); }
.tally .suggest_close b, .tally .auto_close b { color: var(--close); }

.docket { list-style: none; margin: 14px 0 0; padding: 0; counter-reset: entry; }
.entry { display: grid; grid-template-columns: 54px minmax(0, 1fr) auto; gap: 6px 18px; align-items: center;
         padding: 16px 18px 16px 0; border-bottom: 1px solid var(--rule); position: relative;
         animation: rise .55s cubic-bezier(.2,.7,.2,1) both; animation-delay: calc(var(--i) * 45ms + 120ms); }
.entry::before { counter-increment: entry; content: "No." counter(entry, decimal-leading-zero);
                 font: 500 11px var(--mono); color: var(--ink-soft); align-self: start; padding-top: 6px; }
.entry:hover { background: linear-gradient(90deg, var(--card), transparent); }
.entry .title { font: 600 19px/1.25 var(--body); }
.entry .title a { text-decoration: none; } .entry .title a:hover { text-decoration: underline; }
.entry .meta { grid-column: 2; font: 400 12px/1.6 var(--mono); color: var(--ink-soft); word-break: break-all; }
.entry .why { grid-column: 2 / 4; font: italic 15px/1.4 var(--body); color: var(--ink-soft); }
.empty { font-style: italic; color: var(--ink-soft); padding: 18px 0; }

.stamp { font: 600 11px/1 var(--label); letter-spacing: .2em; text-transform: uppercase; white-space: nowrap;
         padding: 7px 10px 6px; border: 2px solid currentColor; border-radius: 3px; transform: rotate(-4deg);
         mix-blend-mode: multiply; opacity: .92; animation: stamp .42s cubic-bezier(.3,1.6,.5,1) both;
         animation-delay: calc(var(--i, 0) * 45ms + 380ms); box-shadow: inset 0 0 0 1px currentColor; }
@media (prefers-color-scheme: dark) { .stamp { mix-blend-mode: normal; } }
.stamp.escalate { color: var(--escalate); } .stamp.investigate { color: var(--investigate); }
.stamp.suggest_close, .stamp.auto_close { color: var(--close); }
.stamp.scored_only { color: var(--ink-soft); }

.exhibit { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 40px; margin-top: 30px; }
.panel { background: var(--card); box-shadow: var(--shadow); padding: 26px 28px; position: relative;
         animation: rise .6s cubic-bezier(.2,.7,.2,1) both; animation-delay: calc(var(--i, 0) * 90ms + 150ms); }
.panel h3 { margin: 0 0 14px; font: 600 11px var(--label); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-soft); }
.finding { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; margin-bottom: 18px; }
.finding .verdict { font: 400 40px/1 var(--display); text-transform: capitalize; }
.gauge { flex: 1; min-width: 160px; }
.gauge i { display: block; height: 4px; background: var(--rule); position: relative; overflow: hidden; }
.gauge i::after { content: ""; position: absolute; inset: 0 auto 0 0; width: var(--v); background: var(--ink);
                  animation: fill 1s .5s cubic-bezier(.2,.7,.2,1) both; }
.gauge small { font: 400 11px var(--mono); color: var(--ink-soft); }
blockquote { margin: 0 0 18px; padding: 0 0 0 22px; border-left: 2px solid var(--margin);
             font: italic 400 21px/1.45 var(--body); position: relative; }
blockquote::before { content: "\\201C"; position: absolute; left: -6px; top: -26px; font: 400 64px var(--display); color: var(--margin); opacity: .35; }
dl { margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; font-size: 15px; }
dt { font: 600 11px/1.9 var(--label); letter-spacing: .14em; text-transform: uppercase; color: var(--ink-soft); }
dd { margin: 0; word-break: break-word; }
.checks { list-style: none; margin: 0; padding: 0; }
.checks li { display: grid; grid-template-columns: 26px 1fr; padding: 7px 0; border-bottom: 1px dashed var(--rule); font-size: 15px; }
.checks li::before { font: 500 14px var(--mono); }
.checks .pass::before { content: "\\2713"; color: var(--close); }
.checks .fail::before { content: "\\2717"; color: var(--escalate); }
.checks .fail { color: var(--escalate); }
.checks.steps li { display: block; overflow-wrap: anywhere; }
.checks small { grid-column: 2; font: 400 11px var(--mono); color: var(--ink-soft); word-break: break-all; }
.tags { display: flex; flex-wrap: wrap; gap: 6px; }
.tags span { font: 400 11px var(--mono); padding: 3px 8px; border: 1px solid var(--rule); background: var(--paper); }
.evidence { margin-top: 40px; --i: 3; }
.evidence table { width: 100%; border-collapse: collapse; font: 400 12px/1.55 var(--mono); }
.evidence th { text-align: left; font-weight: 500; color: var(--ink-soft); padding: 6px 16px 6px 0; vertical-align: top; width: 1%; white-space: nowrap; }
.evidence td { padding: 6px 0; word-break: break-all; }
.evidence tr + tr { border-top: 1px solid var(--rule); }
.scroll { overflow-x: auto; }
.decide { margin-top: 18px; display: grid; gap: 10px; }
.decide input { font: 400 13px var(--mono); padding: 9px 10px; background: var(--paper); color: var(--ink); border: 1px solid var(--ink-soft); }
.decide .buttons { display: flex; gap: 10px; }
.decide button { flex: 1; font: 600 12px var(--label); letter-spacing: .16em; text-transform: uppercase; cursor: pointer;
                 padding: 11px; border: 2px solid currentColor; background: transparent; transition: transform .15s, background .15s; }
.decide button:hover { transform: translateY(-1px); }
.decide .accept { color: var(--close); } .decide .reject { color: var(--escalate); }
.decide output { font: italic 14px var(--body); color: var(--ink-soft); min-height: 1.4em; }
footer { margin-top: 72px; padding-top: 16px; border-top: 1px solid var(--ink); font: 400 12px/1.7 var(--mono); color: var(--ink-soft);
         display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.back { font: 600 12px var(--label); letter-spacing: .18em; text-transform: uppercase; text-decoration: none; }

.cta { display: inline-flex; align-items: center; gap: 10px; margin-top: 26px; padding: 12px 18px; text-decoration: none;
       font: 600 12px var(--label); letter-spacing: .18em; text-transform: uppercase; color: var(--paper); background: var(--ink);
       box-shadow: 4px 4px 0 var(--margin); transition: transform .15s, box-shadow .15s; }
.cta:hover { transform: translate(-2px, -2px); box-shadow: 6px 6px 0 var(--margin); }
.files { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 22px; margin-top: 18px; }
.file { position: relative; background: var(--card); box-shadow: var(--shadow); padding: 30px 20px 18px; margin-top: 14px;
        display: flex; flex-direction: column; gap: 10px; animation: rise .55s cubic-bezier(.2,.7,.2,1) both;
        animation-delay: calc(var(--i) * 70ms + 150ms); }
.file::before { content: attr(data-tab); position: absolute; top: -14px; left: 0; padding: 4px 12px 3px; background: var(--card);
                font: 500 10px var(--mono); color: var(--ink-soft); letter-spacing: .06em; border-radius: 4px 4px 0 0;
                max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file b { font: 400 22px/1.15 var(--display); }
.file p { margin: 0; font-size: 15px; color: var(--ink-soft); flex: 1; }
.file button, .bag button { align-self: flex-start; font: 600 11px var(--label); letter-spacing: .18em; text-transform: uppercase;
        padding: 9px 14px; border: 2px solid var(--ink); background: transparent; color: var(--ink); cursor: pointer; }
.file button:hover, .bag button:hover { background: var(--ink); color: var(--paper); }
.bag { margin-top: 18px; padding: 26px; border: 2px dashed var(--ink-soft); background:
       repeating-linear-gradient(-45deg, transparent 0 14px, var(--rule) 14px 15px), var(--card);
       display: grid; gap: 14px; animation: rise .55s .35s cubic-bezier(.2,.7,.2,1) both; }
.bag.over { border-color: var(--margin); }
.bag input[type=file] { font: 400 13px var(--mono); color: var(--ink); }
.bag label { display: flex; gap: 10px; align-items: flex-start; font-size: 15px; }
.bag label input { margin-top: 5px; accent-color: var(--margin); }
.warning { border-left: 3px solid var(--escalate); padding: 4px 0 4px 14px; font-size: 15px; }
.warning b { color: var(--escalate); }
.status { display: flex; flex-wrap: wrap; gap: 10px 22px; align-items: center; margin-top: 22px; font: 400 13px var(--mono); color: var(--ink-soft); }
.status .pulse { width: 9px; height: 9px; border-radius: 50%; background: var(--investigate); animation: pulse 1.4s infinite; }
.status.failed { color: var(--escalate); }
.progress { height: 4px; background: var(--rule); margin-top: 12px; position: relative; }
.progress i { position: absolute; inset: 0 auto 0 0; width: var(--v); background: var(--margin); transition: width .4s; }

details.group { border-bottom: 1px solid var(--rule); padding: 12px 0; }
details.group summary { cursor: pointer; display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; list-style: none; }
details.group summary::-webkit-details-marker { display: none; }
details.group summary::before { content: "+"; font: 500 14px var(--mono); color: var(--margin); width: 14px; }
details.group[open] summary::before { content: "2"; }
details.group summary b { font: 600 18px var(--body); }
details.group summary span { font: 400 12px var(--mono); color: var(--ink-soft); }
details.group ol { margin: 10px 0 0 28px; padding: 0; font: 400 12px/1.9 var(--mono); }

@keyframes rise { from { opacity: 0; transform: translateY(10px); } }
@keyframes pulse { 50% { opacity: .25; } }
@keyframes stamp { 0% { opacity: 0; transform: rotate(-14deg) scale(1.9); } 70% { opacity: .92; } 100% { transform: rotate(-4deg) scale(1); } }
@keyframes fill { from { width: 0; } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
@media (max-width: 760px) {
  body { --gutter: 18px; font-size: 16px; }
  main { padding: 28px 16px 60px 34px; }
  .entry { grid-template-columns: minmax(0, 1fr) auto; padding-right: 0; }
  .entry::before { grid-column: 1 / -1; padding: 0; }
  .entry .meta { grid-column: 1; } .entry .why { grid-column: 1 / -1; }
  .exhibit { grid-template-columns: 1fr; gap: 24px; }
  .panel { padding: 20px; }
}
"""

_DECIDE_JS = """
document.querySelectorAll('form.decide').forEach(function (form) {
  form.addEventListener('submit', function (e) { e.preventDefault(); });
  form.querySelectorAll('button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var out = form.querySelector('output');
      out.textContent = 'Recording…';
      fetch('/api/alerts/' + encodeURIComponent(form.dataset.alert) + '/decision', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + form.token.value},
        body: JSON.stringify({decision: btn.value, analyst: form.analyst.value || 'analyst'})
      }).then(function (r) {
        if (r.ok) { location.reload(); return; }
        out.textContent = r.status === 401 ? 'That token was not accepted.' :
                          r.status === 503 ? 'Decisions are switched off on this deployment.' :
                          'Not recorded (HTTP ' + r.status + ').';
      }).catch(function () { out.textContent = 'Could not reach the server.'; });
    });
  });
});
"""


def _page(title: str, body: str, script: str = "", refresh: int | None = None) -> str:
    tail = f"<script>{script}</script>" if script else ""
    meta = f"<meta http-equiv='refresh' content='{refresh}'>" if refresh else ""
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>{meta}"
            f"<title>{escape(title)}</title><link rel='preconnect' href='https://fonts.googleapis.com'>"
            f"<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin><link rel='stylesheet' href='{FONTS}'>"
            f"<style>{_STYLE}</style></head><body><main>{body}{_footer()}</main>{tail}</body></html>")


def _footer() -> str:
    return (f"<footer><span>Probative AI · the model proposes, code decides</span>"
            f"<span><a href='{REPO}'>source</a> · <a href='/health'>health</a> · <a href='/api/queue'>json</a></span></footer>")


def _stamp(route: str, i: int = 0) -> str:
    return f"<span class='stamp {escape(route)}' style='--i:{i}'>{escape(ROUTE_LABEL.get(route, route))}</span>"


def _docket(rows: list[dict[str, Any]], offset: int) -> str:
    if not rows:
        return "<p class='empty'>No entries on this docket.</p>"
    items = []
    for n, r in enumerate(rows):
        i = n + offset
        alert_id = escape(r["alert_id"])
        error = (r.get("judge_result") or {}).get("error") or ""
        reasons = "AI not run (budget): scored and escalated" if error.startswith("AI not run") else ", ".join(r["reasons"])
        items.append(
            f"<li class='entry' style='--i:{i}'>"
            f"<div class='title'><a href='/alerts/{alert_id}'>{escape(r['rule_title'])}</a></div>"
            f"{_stamp(r['route'], i)}"
            f"<div class='meta'>{alert_id} · {escape(r['host'])} · {escape(str(r['ts'])[:19])}</div>"
            + (f"<div class='why'>{escape(reasons)}</div>" if reasons else "") + "</li>")
    return f"<ol class='docket'>{''.join(items)}</ol>"


def home(counts: dict[str, int], analyst_queue: list[dict], suggestions: list[dict]) -> str:
    order = ["escalate", "investigate", "suggest_close", "auto_close"]
    tally = "".join(f"<div class='{escape(route)}'><b>{counts.get(route, 0)}</b><span>{escape(ROUTE_LABEL[route])}</span></div>"
                    for route in order if route in counts or route != "auto_close")
    body = (
        "<div class='kicker'>Tier-1 alert docket · public OTRF data · shadow mode</div>"
        "<h1>Probative <em>AI</em></h1>"
        "<p class='lede'>Every alert is read by a deterministic pipeline, judged once by a language model that may only "
        "<i>propose</i>, then cross-examined by seven checks in code. Nothing closes without a human. "
        "Scenario: <code>empire_mimikatz_logonpasswords</code>.</p>"
        "<p class='procedure'><b>detect</b> → parse → noise → process-scoped context → enrich → "
        "<b>evidence score</b> → <span class='model'>one LLM judgment</span> → <b>verifier</b> → route → human</p>"
        "<a class='cta' href='/try'>Try it on an attack recording or your own log →</a>"
        f"<div class='tally'>{tally}</div>"
        f"<h2>Analyst queue <span class='count'>{len(analyst_queue)} open</span></h2>{_docket(analyst_queue, 0)}"
        f"<h2>Suggested closes <span class='count'>{len(suggestions)} awaiting a human</span></h2>"
        f"{_docket(suggestions, len(analyst_queue))}")
    return _page("Probative AI · alert docket", body)


def _decide_form(alert_id: str) -> str:
    return (f"<form class='decide' data-alert='{escape(alert_id)}'>"
            "<input name='analyst' placeholder='your name' maxlength='100' autocomplete='name'>"
            "<input name='token' type='password' placeholder='demo API token' autocomplete='off'>"
            "<div class='buttons'><button class='accept' value='accept'>Accept close</button>"
            "<button class='reject' value='reject'>Reject</button></div><output></output></form>")


def alert(detail: dict[str, Any]) -> str:
    a, verdict, trigger = detail["alert"], detail["verdict"], detail["trigger_event"]
    case_id = detail.get("case_id")
    back = (f"<a class='back' href='/cases/{escape(case_id)}'>← Case</a>" if case_id
            else "<a class='back' href='/'>← Docket</a>")
    head = (back +
            f"<div class='kicker' style='margin-top:28px'>Exhibit · {escape(a['alert_id'])}</div>"
            f"<h1 style='font-size:clamp(34px,5vw,58px)'>{escape(a['rule_title'])}</h1>"
            f"<p class='lede mono'>{escape(a['host'])} · {escape(a['timestamp'])} · level {escape(a['rule_level'])}"
            + (f" · user {escape(a['user'])}" if a.get("user") else "") + "</p>")

    if not verdict:
        finding = "<section class='panel'><h3>Finding</h3><p class='empty'>Not yet triaged.</p></section>"
        checks = ""
    else:
        result, v = verdict["judge_result"], verdict["judge_result"].get("verdict")
        parts = [f"<section class='panel' style='--i:0'><h3>Finding</h3><div class='finding'>{_stamp(verdict['route'])}"]
        if v:
            parts.append(f"<span class='verdict'>{escape(v['verdict'])}</span>"
                         f"<div class='gauge'><i style='--v:{float(v['confidence']) * 100:.0f}%'></i>"
                         f"<small>model confidence {escape(str(v['confidence']))}</small></div></div>"
                         f"<blockquote>{escape(v['summary'])}</blockquote>"
                         f"<dl><dt>Cited</dt><dd class='mono'>{escape(', '.join(v['cited_event_ids']) or 'nothing')}</dd>"
                         f"<dt>Would settle it</dt><dd>{escape('; '.join(v['missing_context']) or 'nothing further asked')}</dd>")
        else:
            error = result.get("error") or "unknown"
            if error.startswith(_SKIPPED):
                parts.append("</div><blockquote>Not reviewed by AI: only the highest-scoring alerts of a sandbox case are, "
                             "to stay inside the free model budget. Without a verdict it stays with the analyst; "
                             "it is never treated as safe.</blockquote><dl>")
            else:
                parts.append(f"</div><blockquote>The judge returned no verdict: {escape(error)}</blockquote><dl>")
        parts.append(f"<dt>Routed because</dt><dd>{escape(', '.join(verdict['reasons']) or '-')}</dd>"
                     f"<dt>Evidence score</dt><dd><b>{escape(str(verdict['score']['total']))}</b> "
                     f"<span class='tags'>{''.join(f'<span>{escape(s)}</span>' for s in verdict['score']['contributions'])}</span></dd>")
        if detail.get("decision"):
            d = detail["decision"]
            parts.append(f"<dt>Human decision</dt><dd>{escape(d['decision'])} by {escape(d['analyst'])}</dd>")
        parts.append("</dl>")
        if verdict["route"] == "suggest_close" and not detail.get("decision") and not case_id:
            parts.append(_decide_form(a["alert_id"]))
        parts.append("</section>")
        finding = "".join(parts)
        items = "".join(
            f"<li class='{'pass' if c['passed'] else 'fail'}'>{escape(CHECK_LABEL.get(c['name'], c['name']))}"
            + (f"<small>{escape(c['detail'])}</small>" if c.get("detail") and not c["passed"] else "") + "</li>"
            for c in verdict["report"]["checks"])
        checks = f"<section class='panel' style='--i:1'><h3>Cross-examination · seven checks</h3><ul class='checks'>{items}</ul></section>"

    investigation = _investigation_panel(detail.get("investigation"))
    rows = "".join(f"<tr><th>{escape(str(k))}</th><td>{escape(str(val)[:500])}</td></tr>"
                   for k, val in trigger["fields"].items() if k != "Message")
    evidence = (f"<section class='panel evidence'><h3>Exhibit A · triggering event "
                f"<span class='mono'>{escape(trigger['event_id'])}</span></h3><div class='scroll'><table>{rows}</table></div></section>")
    script = _DECIDE_JS if "class='decide'" in finding else ""
    return _page(f"{a['rule_title']} · Probative AI",
                 head + f"<div class='exhibit'>{finding}{checks}</div>" + investigation + evidence, script)


_TRY_JS = """
function post(url, opts, out) {
  out.textContent = 'Opening a case…';
  fetch(url, Object.assign({method: 'POST'}, opts)).then(function (r) {
    return r.json().then(function (b) { return {ok: r.ok, body: b}; });
  }).then(function (res) {
    if (res.ok) { location.href = res.body.url; return; }
    out.textContent = res.body.detail || 'That did not work.';
  }).catch(function () { out.textContent = 'Could not reach the server.'; });
}
document.querySelectorAll('[data-scenario]').forEach(function (btn) {
  btn.addEventListener('click', function () {
    post('/api/cases/scenario/' + encodeURIComponent(btn.dataset.scenario), {}, document.getElementById('scenario-out'));
  });
});
var bag = document.getElementById('bag');
bag.addEventListener('submit', function (e) {
  e.preventDefault();
  var out = bag.querySelector('output'), file = bag.file.files[0];
  if (!file) { out.textContent = 'Choose a file first.'; return; }
  if (!bag.declared.checked) { out.textContent = 'Tick the box to confirm the file has no private data.'; return; }
  if (file.size > Number(bag.dataset.max)) { out.textContent = 'That file is larger than the sandbox allows.'; return; }
  post('/api/cases/upload', {headers: {'X-Declared-Public': 'yes', 'X-Filename': encodeURIComponent(file.name)},
                             body: file}, out);
});
['dragover', 'dragenter'].forEach(function (t) { bag.addEventListener(t, function (e) { e.preventDefault(); bag.classList.add('over'); }); });
['dragleave', 'drop'].forEach(function (t) { bag.addEventListener(t, function () { bag.classList.remove('over'); }); });
bag.addEventListener('drop', function (e) { e.preventDefault(); if (e.dataTransfer.files.length) bag.file.files = e.dataTransfer.files; });
"""


def try_page(scenarios: dict, max_bytes: int) -> str:
    files = "".join(
        f"<div class='file' style='--i:{i}' data-tab='OTRF · {escape(key)}'><b>{escape(s.title)}</b><p>{escape(s.blurb)}</p>"
        f"<button type='button' data-scenario='{escape(key)}'>Open this case</button></div>"
        for i, (key, s) in enumerate(scenarios.items()))
    body = (
        "<a class='back' href='/'>← Docket</a>"
        "<div class='kicker' style='margin-top:28px'>Sandbox · cases expire after 24 hours</div>"
        "<h1>Open a <em>case</em></h1>"
        "<p class='lede'>Run the full pipeline on a recorded attack, or on a Windows log of your own: Sigma detection, "
        "process-scoped evidence, a deterministic score for every alert, and an AI verdict, cross-examined in code, "
        "for the five strongest. You get a private link to the results.</p>"
        "<h2>A public attack recording</h2>"
        "<p class='lede'>Real lab recordings from the Open Threat Research Forge (OTRF Security-Datasets).</p>"
        f"<div class='files'>{files}</div><p><output id='scenario-out' class='muted'></output></p>"
        "<h2>Your own log</h2>"
        f"<form id='bag' class='bag' data-max='{max_bytes}'>"
        "<div class='warning'><b>Do not upload company, customer or personal logs.</b> Logs carry usernames, hostnames "
        "and addresses. The five strongest alerts are sent to a cloud AI model, and the case is stored for 24 hours. "
        "Use your own lab, a test VM, or a public dataset.</div>"
        f"<input type='file' name='file' accept='.evtx,.json,.jsonl'>"
        f"<p class='muted' style='margin:0;font-size:14px'>A Windows <code class='mono'>.evtx</code> file (Sysmon or Security "
        f"work best) or OTRF-style JSON lines, up to {max_bytes // (1024 * 1024)} MB. Drop it here or choose it.</p>"
        "<label><input type='checkbox' name='declared'> I confirm this file contains no private or confidential "
        "data, and I am allowed to share it.</label>"
        "<button type='submit'>Open a case from this file</button><output class='muted'></output></form>")
    return _page("Open a case · Probative AI", body, _TRY_JS)


def case(case: dict, triaged: int, analyst_queue: list[dict], suggestions: list[dict]) -> str:
    status, n_alerts = case["status"], case["n_alerts"]
    working = status in ("queued", "processing") or (status == "ready" and triaged < n_alerts)
    if status == "failed":
        line = f"<div class='status failed'>Could not process this file: {escape(case['detail'] or 'unknown error')}</div>"
    elif status in ("queued", "processing"):
        line = (f"<div class='status'><span class='pulse'></span>{escape(case['detail'] or 'Reading the file and running Sigma detection')}"
                "… this page refreshes itself.</div>")
    else:
        pct = 100 * triaged / n_alerts if n_alerts else 100
        line = (f"<div class='status'>{'<span class=pulse></span>' if working else ''}"
                f"{case['n_events']:,} events · {n_alerts} alerts · {triaged} triaged"
                f"{' · refreshing' if working else ''}</div><div class='progress'><i style='--v:{pct:.0f}%'></i></div>")
        if case["detail"]:
            line += f"<p class='lede' style='margin-top:16px'>Note: {escape(case['detail'])}.</p>"
        if n_alerts == 0:
            line += "<p class='lede' style='margin-top:16px'>No Sigma rule above informational level fired on this file.</p>"
    body = (
        "<a class='back' href='/try'>← Open another case</a>"
        f"<div class='kicker' style='margin-top:28px'>Case · {escape(case['source'])} · expires {escape(str(case['expires_at'])[:16])} UTC</div>"
        f"<h1 style='font-size:clamp(34px,5vw,58px)'>{escape(case['name'])}</h1>{line}"
        + _case_sections(analyst_queue + suggestions))
    return _page(f"{case['name']} · Probative AI case", body, refresh=5 if working else None)


def _skipped(row: dict) -> bool:
    return ((row.get("judge_result") or {}).get("error") or "").startswith(_SKIPPED)


def _case_sections(rows: list[dict]) -> str:
    """The AI-reviewed alerts first (highest score first), then the rest grouped by rule."""
    score = lambda r: float((r.get("score") or {}).get("total", 0))  # noqa: E731
    reviewed = sorted((r for r in rows if not _skipped(r)), key=lambda r: (-score(r), str(r["ts"])))
    skipped = [r for r in rows if _skipped(r)]
    html = [f"<h2>Reviewed by AI <span class='count'>{len(reviewed)}</span></h2>", _docket(reviewed, 0)]
    if skipped:
        groups: dict[str, list[dict]] = {}
        for r in sorted(skipped, key=lambda r: (-score(r), str(r["ts"]))):
            groups.setdefault(r["rule_title"], []).append(r)
        html.append(f"<h2>Scored only <span class='count'>{len(skipped)} not reviewed by AI</span></h2>"
                    "<p class='lede'>AI not run on these: only the five highest-scoring alerts of a case get an AI "
                    "verdict. Each was still scored by the deterministic pipeline, and without a verdict it stays "
                    "with the analyst; it is never treated as safe.</p>")
        for n, (rule, items) in enumerate(sorted(groups.items(), key=lambda kv: (-max(map(score, kv[1])), kv[0]))):
            links = "".join(f"<li><a href='/alerts/{escape(r['alert_id'])}'>{escape(r['host'])} · "
                            f"{escape(str(r['ts'])[:19])} · score {score(r):g}</a></li>" for r in items)
            html.append(f"<details class='group'><summary>{_stamp('scored_only', n)}<b>{escape(rule)} × {len(items)}</b>"
                        f"<span>score {min(map(score, items)):g}–{max(map(score, items)):g}</span></summary>"
                        f"<ol>{links}</ol></details>")
    return "".join(html)


def _investigation_panel(inv: dict | None) -> str:
    """The bounded investigator's steps and how it ended."""
    if not inv:
        return ""
    state = inv["state"]
    steps = []
    for n, q in enumerate(state["query_log"], 1):
        args = ", ".join(f"{k}={v}" for k, v in q["arguments"].items())
        if q.get("error"):
            outcome = f"<span class='fail'>rejected: {escape(q['error'])}</span>"
        else:
            found = [f"+{len(q['result_event_ids'])} events"] + [escape(i) for i in q.get("intel", [])]
            outcome = escape(", ".join(found))
        steps.append(f"<li><b class='mono'>{n}. {escape(q['tool'])}</b>(<span class='mono'>{escape(args)}</span>) "
                     f"<span class='muted'>→</span> {outcome}</li>")
    v = (inv.get("result") or {}).get("verdict")
    if inv["verified"] and v:
        ending = (f"<p><b>Ended:</b> verified verdict, <b>{escape(v['verdict'])}</b> "
                  f"(confidence {escape(str(v['confidence']))}).</p><blockquote>{escape(v['summary'])}</blockquote>")
    else:
        ending = (f"<p><b>Ended:</b> {escape(inv['stop_reason'])}. Handed to the analyst with this log; "
                  "the investigator never closes an alert it could not verify.</p>")
    return (f"<section class='panel evidence' style='--i:2'><h3>Investigation · {state['step_count']} steps · "
            f"{state['tokens_used']:,} tokens · read-only tools</h3><ol class='checks steps'>{''.join(steps)}</ol>"
            f"{ending}</section>")
