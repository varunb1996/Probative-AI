"""Server-rendered analyst pages. Log text is hostile, so every value goes through escape()."""

from html import escape
from typing import Any

_STYLE = """
:root { --bg: #fafafa; --fg: #1a1a1a; --muted: #666; --line: #ddd; --card: #fff; --bad: #b42318; --ok: #067647; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #111; --fg: #eee; --muted: #999; --line: #333; --card: #1a1a1a; --bad: #f97066; --ok: #47cd89; }
}
body { font: 15px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 24px 16px; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 28px 0 8px; }
p.muted, .muted { color: var(--muted); }
.cards { display: flex; gap: 12px; flex-wrap: wrap; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; min-width: 120px; }
.card b { display: block; font-size: 22px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; background: var(--card); }
th, td { border-bottom: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
th { font-weight: 600; } code { font-size: 13px; word-break: break-all; }
.escalate, .investigate { color: var(--bad); } .suggest_close, .auto_close { color: var(--ok); }
a { color: inherit; }
"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body><main>{body}</main></body></html>")


def _rows_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p class='muted'>Nothing here.</p>"
    lines = ["<div class='scroll'><table><tr><th>Alert</th><th>Rule</th><th>Host</th><th>Time</th>"
             "<th>Route</th><th>Why</th></tr>"]
    for r in rows:
        alert_id = escape(r["alert_id"])
        lines.append(
            f"<tr><td><a href='/alerts/{alert_id}'><code>{alert_id}</code></a></td>"
            f"<td>{escape(r['rule_title'])}</td><td>{escape(r['host'])}</td><td>{escape(str(r['ts']))}</td>"
            f"<td class='{escape(r['route'])}'>{escape(r['route'])}</td>"
            f"<td>{escape(', '.join(r['reasons']))}</td></tr>")
    lines.append("</table></div>")
    return "".join(lines)


def home(counts: dict[str, int], analyst_queue: list[dict], suggestions: list[dict]) -> str:
    cards = "".join(f"<div class='card'><b>{n}</b>{escape(name)}</div>" for name, n in counts.items())
    return _page("Probative AI", (
        "<h1>Probative AI</h1>"
        "<p class='muted'>Tier-1 alert triage: a deterministic pipeline, one LLM judgment, and a code-owned "
        "verifier. Data: public OTRF <code>empire_mimikatz_logonpasswords</code>. Shadow mode: nothing is "
        "closed without a human. Decisions need the demo API token.</p>"
        f"<div class='cards'>{cards}</div>"
        f"<h2>Analyst queue ({len(analyst_queue)})</h2>{_rows_table(analyst_queue)}"
        f"<h2>Suggested closes ({len(suggestions)})</h2>{_rows_table(suggestions)}"))


def alert(detail: dict[str, Any]) -> str:
    a, verdict, trigger = detail["alert"], detail["verdict"], detail["trigger_event"]
    parts = [f"<p><a href='/'>&larr; queues</a></p><h1>{escape(a['rule_title'])}</h1>",
             f"<p class='muted'><code>{escape(a['alert_id'])}</code> · {escape(a['host'])} · "
             f"{escape(a['timestamp'])} · level {escape(a['rule_level'])}</p>"]
    if verdict:
        result = verdict["judge_result"]
        v = result.get("verdict")
        failed = [c["name"] for c in verdict["report"]["checks"] if not c["passed"]]
        parts.append(
            f"<h2>Route: <span class='{escape(verdict['route'])}'>{escape(verdict['route'])}</span></h2>"
            f"<p>{escape(', '.join(verdict['reasons']))}</p>")
        if v:
            parts.append(
                f"<p><b>Model verdict:</b> {escape(v['verdict'])} (confidence {escape(str(v['confidence']))})"
                f"<br>{escape(v['summary'])}</p>"
                f"<p><b>Cited:</b> {escape(', '.join(v['cited_event_ids']))}</p>"
                f"<p><b>Missing context:</b> {escape('; '.join(v['missing_context']) or 'none')}</p>")
        else:
            parts.append(f"<p><b>Judge failed:</b> {escape(result.get('error') or '')}</p>")
        parts.append(f"<p><b>Failed checks:</b> {escape(', '.join(failed) or 'none')}</p>"
                     f"<p><b>Evidence score:</b> {escape(str(verdict['score']['total']))} "
                     f"({escape(', '.join(verdict['score']['contributions']))})</p>")
    else:
        parts.append("<p class='muted'>Not triaged yet.</p>")
    if detail.get("decision"):
        d = detail["decision"]
        parts.append(f"<p><b>Human decision:</b> {escape(d['decision'])} by {escape(d['analyst'])}</p>")
    fields = "".join(f"<tr><th>{escape(str(k))}</th><td><code>{escape(str(val)[:500])}</code></td></tr>"
                     for k, val in trigger["fields"].items())
    parts.append(f"<h2>Triggering event <code>{escape(trigger['event_id'])}</code></h2>"
                 f"<div class='scroll'><table>{fields}</table></div>")
    return _page(f"{a['rule_title']} · Probative AI", "".join(parts))
