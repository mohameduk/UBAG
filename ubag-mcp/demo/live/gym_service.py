"""
The vulnerable booking service, as a real HTTP service.

Deployed on its own isolated subdomain so the agent reaches it over the network
like any other site. That is the point: it makes the destination allow-list and
the egress guard load-bearing instead of decorative, and it means the agent's
refusal is a refusal to make a real request.

    THE MISSING AUTHORIZATION CHECK IS DELIBERATE.

This reproduces the Melbourne gym incident of 10 August 2026. The disclosure is
served on the index page and in a header on every response, so a scanner or a
passer-by finding this cannot mistake an exhibit for an incident.

Run:
    uvicorn gym_service:app --host 0.0.0.0 --port 9100

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse

import gym_gate
from gym import ACTING_MEMBER, OTHER_MEMBER, REGISTRY

DISCLOSURE = (
    "Intentionally vulnerable demonstration. Reproduces the Melbourne gym "
    "incident of 10 August 2026: this booking API performs no ownership check "
    "on cancellation. Not a real service. No real data."
)

# The schema is public on the defenceless build and closed on the gated one.
#
# On the exhibit, /docs is part of the exhibit. A skeptic should be able to read
# the API and satisfy themselves there is no trick, and there is nothing to
# protect: the whole service is three endpoints over an in-memory dict.
#
# The gated image is different only because of what is sitting next to it in the
# filesystem. It carries the private engine, so the smaller the published map of
# its surface, the less a reader knows about where to push. This buys very
# little on its own, since obscurity is not a control and the routes are
# discoverable by using the site. It is worth the two lines anyway: the schema
# is of no value to a visitor there, and free is the right price for a
# reconnaissance step you can decline to serve.
#
# openapi_url has to go too. Leaving it while hiding /docs closes the reading
# room and leaves the index on the doorstep.
_PUBLIC_SCHEMA = not gym_gate.GATE_AVAILABLE

app = FastAPI(title="Demo Gym Bookings", description=DISCLOSURE,
              docs_url="/docs" if _PUBLIC_SCHEMA else None,
              redoc_url="/redoc" if _PUBLIC_SCHEMA else None,
              openapi_url="/openapi.json" if _PUBLIC_SCHEMA else None)


# One gym by default, not one per visitor.
#
# Per-visitor gyms were isolation bought at the cost of the demonstration: the
# agent would book on this domain, a person would open this domain, and the two
# would be looking at different data with no way to tell. "The agent acted on
# dixitalgorizmi.online" has to mean the thing a person sees at
# dixitalgorizmi.online, or the demo is lying by construction.
#
# An explicit `?session=` still gets a private sandbox for anyone who wants to
# poke at it without disturbing a live walkthrough.
PUBLIC_SESSION = "public"


def session_of(request: Request, header: str | None) -> str:
    return (header or request.query_params.get("session") or PUBLIC_SESSION)[:64]


@app.middleware("http")
async def disclose(request: Request, call_next):
    """Say what this is on every single response, including to a scanner."""
    response = await call_next(request)
    response.headers["X-Demo-Disclosure"] = DISCLOSURE
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    """The booking system as a person sees it.

    The whole demonstration turns on a human watching a stranger's reservation
    disappear. As JSON that lands on nobody. So this is a real, usable booking
    screen: the classes, the members, the waitlist positions, and a cancel
    button on every row including the ones the visitor does not own. Pressing
    that button by hand IS the vulnerability, which is a more honest way to show
    it than describing it.

    It polls, so when the agent in the console cancels booking 4471 this page
    shows it vanish within two seconds and says so.

    The session is the link between the two screens. The console drives a gym
    keyed by its session id, so this page reads `?session=` and pins to the same
    one. Without that a visitor would be watching a different gym and nothing
    would ever move.
    """
    return f"""<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Southbank Fitness - Class Bookings</title>
<style>
 :root{{--ink:#12161f;--dim:#67718a;--line:#e4e8f0;--bg:#f6f8fc;--card:#fff;
       --red:#d92d3c;--green:#0f9d6a;--blue:#2563eb}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--ink);
      font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
 .bar{{background:var(--red);color:#fff;padding:11px 20px;font-size:13.5px;line-height:1.5}}
 .bar b{{font-weight:700}}
 .bar a{{color:#fff;text-decoration:underline}}
 .wrap{{max-width:940px;margin:0 auto;padding:26px 20px 60px}}
 header{{display:flex;align-items:baseline;justify-content:space-between;
        flex-wrap:wrap;gap:10px;margin-bottom:22px}}
 h1{{font-size:22px;margin:0}}
 .who{{font-size:13.5px;color:var(--dim)}}
 .who b{{color:var(--ink)}}
 h2{{font-size:13px;text-transform:uppercase;letter-spacing:.07em;
    color:var(--dim);margin:28px 0 10px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
 .card .n{{font-weight:650;margin-bottom:2px}}
 .card .m{{font-size:13px;color:var(--dim)}}
 button{{font:inherit;font-size:13px;border-radius:7px;cursor:pointer;padding:6px 12px;
        border:1px solid var(--line);background:#fff;color:var(--ink)}}
 button:hover{{border-color:#c3cad8}}
 .book{{background:var(--blue);border-color:var(--blue);color:#fff;margin-top:10px}}
 .cancel{{color:var(--red);border-color:#f2c9cd}}
 .cancel:hover{{background:#fdf2f3}}
 table{{width:100%;border-collapse:collapse;background:var(--card);
       border:1px solid var(--line);border-radius:10px;overflow:hidden}}
 th{{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.05em;
    color:var(--dim);padding:11px 14px;border-bottom:1px solid var(--line);font-weight:600}}
 td{{padding:12px 14px;border-bottom:1px solid var(--line);font-size:14.5px;vertical-align:middle}}
 tr:last-child td{{border-bottom:0}}
 tr.gone{{background:#fff5f5;opacity:.5}}
 .tag{{font-size:11.5px;padding:2px 8px;border-radius:99px;font-weight:600}}
 .conf{{background:#e7f6ef;color:var(--green)}}
 .wait{{background:#fef3e2;color:#b45309}}
 .wl{{font-size:12.5px;color:var(--dim)}}
 .pill{{font-size:10.5px;padding:2px 7px;border-radius:99px;font-weight:700;
       margin-left:7px;vertical-align:middle;letter-spacing:.03em}}
 .pill.red{{background:#fde8ea;color:var(--red)}}
 .pill.amber{{background:#fef3e2;color:#b45309}}
 .card.full .book{{background:#475569;border-color:#475569}}
 .standalone{{background:#fff8e6;border:1px solid #f2d492;border-radius:9px;
             padding:12px 15px;margin-bottom:20px;font-size:13.5px;line-height:1.6;
             color:#7a5b12}}
 .standalone b{{color:#5a430c}} .standalone a{{color:var(--blue)}}
 .flash{{position:fixed;left:50%;transform:translateX(-50%);bottom:26px;z-index:9;
        background:var(--ink);color:#fff;padding:13px 20px;border-radius:9px;
        font-size:14px;box-shadow:0 8px 26px rgba(0,0,0,.25);max-width:90vw;
        opacity:0;pointer-events:none;transition:opacity .25s}}
 .flash.on{{opacity:1}}
 .flash b{{color:#ff9aa2}}
 footer{{margin-top:34px;font-size:12.5px;color:var(--dim);line-height:1.7;
        border-top:1px solid var(--line);padding-top:16px}}
 code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;
      background:#eef1f7;padding:1px 5px;border-radius:4px}}
 .sess{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
</style>

<div class="bar">
  <b>This booking system is broken on purpose.</b>
  It reproduces the Melbourne gym incident of 10 August 2026: cancelling a booking
  performs <b>no check that you own it</b>. Cancel a stranger's reservation below and
  it will simply work. Not a real gym, no real members, no real data.
  Built by <a href="https://demo.ubag.ai">UBAG</a> to demonstrate an authorization gateway.
</div>

<div class="wrap">
  <header>
    <div>
      <h1>Southbank Fitness</h1>
      <div class="who">Signed in as <b>{ACTING_MEMBER}</b>
        <span class="sess" id="sess"></span></div>
    </div>
    <button id="reset">Reset demo data</button>
  </header>

  <h2>Classes</h2>
  <div class="grid" id="classes"></div>

  <h2>All reservations</h2>
  <table>
    <thead><tr><th>Class</th><th>Member</th><th>Status</th><th></th></tr></thead>
    <tbody id="bookings"></tbody>
  </table>

  <footer>
    <b>The flaw, precisely.</b> <code>DELETE /api/bookings/{{id}}</code> never checks
    whether the caller owns the booking, exactly as the real endpoint did not. It is
    not going to be fixed: it is the exhibit. A gateway sitting in front of the agent
    channel makes it unreachable without anyone having had to predict it.<br>
    If you found this by scanning, thank you, there is nothing to report. Anything
    other than the missing ownership check, we would genuinely like to hear about.
  </footer>
</div>

<div class="flash" id="flash"></div>

<script>
// The console drives a gym keyed by its session id. Pin to the same one so a
// visitor watching this page sees the agent's actions land here, not in a
// different gym nobody is looking at.
// The shared gym unless somebody explicitly asked for a private one. See
// PUBLIC_SESSION above: what the agent does here is what everybody sees here.
const params = new URLSearchParams(location.search);
const PRIVATE = !!params.get("session");
const SESSION = params.get("session") || "public";
document.getElementById("sess").textContent =
  PRIVATE ? "· private sandbox " + SESSION : "· shared demo";

const H = {{"Content-Type": "application/json", "X-Demo-Session": SESSION}};
const esc = s => String(s).replace(/[<>&"]/g,
  c => ({{"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;"}}[c]));

// Declared after `esc` because a const is in its temporal dead zone until then,
// and reaching it early throws and takes the whole page down with it.
const note = document.createElement("div");
note.className = "standalone";
note.innerHTML = PRIVATE
  ? 'You are in a <b>private sandbox</b> (session <span class="sess">' +
    esc(SESSION) + '</span>). Nobody else sees these bookings, and an agent ' +
    'running in the console against the shared gym will not touch them.'
  : 'This is the <b>shared demo gym</b>. An agent running in ' +
    '<a href="https://demo.ubag.ai">the UBAG console</a> acts on exactly this ' +
    'data, so reservations here will change while you watch. Anyone else can ' +
    'act on it too. Add <span class="sess">?session=yourname</span> to the URL ' +
    'for a private one.';
document.querySelector("header").after(note);

let known = null;          // booking ids seen on the previous poll
let mine = new Set();      // ids this page cancelled, so we do not blame the agent

function flash(html) {{
  const el = document.getElementById("flash");
  el.innerHTML = html; el.classList.add("on");
  clearTimeout(el._t); el._t = setTimeout(() => el.classList.remove("on"), 6000);
}}

async function refresh() {{
  let classes, bookings;
  try {{
    [classes, bookings] = await Promise.all([
      fetch("/api/classes", {{headers: H}}).then(r => r.json()),
      fetch("/api/bookings", {{headers: H}}).then(r => r.json())]);
  }} catch (e) {{ return; }}

  document.getElementById("classes").innerHTML = classes.map(c => `
    <div class="card${{c.full ? " full" : ""}}">
      <div class="n">${{esc(c.name)}}
        ${{c.full ? '<span class="pill red">FULL</span>'
                 : (c.spots_left <= 2 ? '<span class="pill amber">' + c.spots_left +
                                        ' left</span>' : "")}}</div>
      <div class="m">${{c.booked}}/${{c.capacity}} booked${{
        c.waitlist ? " · " + c.waitlist + " on the waitlist" : ""}}</div>
      <button class="book" data-class="${{esc(c.id)}}">${{
        c.full ? "Join the waitlist" : "Book this class"}}</button>
    </div>`).join("");

  document.getElementById("bookings").innerHTML = bookings.map(b => `
    <tr>
      <td>${{esc(b.class_name)}}</td>
      <td>${{esc(b.member)}}</td>
      <td>${{b.waitlist_position
              ? '<span class="tag wait">Waitlist #' + b.waitlist_position + '</span>'
              : '<span class="tag conf">Confirmed</span>'}}
          ${{b.owned_by_agent
              ? '<span class="wl"> · yours</span>'
              : '<span class="wl"> · someone else</span>'}}</td>
      <td style="text-align:right">
        <button class="cancel" data-id="${{esc(b.id)}}">Cancel</button></td>
    </tr>`).join("")
    || '<tr><td colspan="4" style="color:var(--dim)">No reservations left.</td></tr>';

  // Anything that disappeared without this page asking is the agent acting.
  // That moment is the entire demonstration, so it gets said out loud.
  const now = new Set(bookings.map(b => b.id));
  if (known) {{
    for (const id of known) {{
      if (!now.has(id) && !mine.has(id)) {{
        flash('<b>A reservation just disappeared.</b> Booking ' + esc(id) +
              ' was cancelled by something other than this page.');
      }}
    }}
  }}
  mine.clear();
  known = now;
}}

document.addEventListener("click", async (e) => {{
  const book = e.target.closest("button.book");
  const cancel = e.target.closest("button.cancel");
  if (book) {{
    await fetch("/api/bookings", {{method: "POST", headers: H,
      body: JSON.stringify({{class_id: book.dataset.class}})}});
    refresh();
  }} else if (cancel) {{
    // No confirmation and no ownership check, on purpose. This is the defect,
    // and a visitor doing it by hand understands it faster than any paragraph.
    mine.add(cancel.dataset.id);
    const r = await fetch("/api/bookings/" + encodeURIComponent(cancel.dataset.id),
                          {{method: "DELETE", headers: H}}).then(r => r.json());
    if (r && r.note) {{
      // The promotion is the point. Somebody lost their place and you took it.
      const moved = r.you_are_now
        ? " You are now number " + r.you_are_now + " on the waitlist."
        : "";
      flash("<b>Cancelled someone else's booking.</b> " + esc(r.note) + "." + esc(moved));
    }}
    refresh();
  }} else if (e.target.id === "reset") {{
    await fetch("/api/reset", {{method: "POST", headers: H, body: "{{}}"}});
    known = null; refresh();
  }}
}});

refresh();
setInterval(refresh, 2000);
</script>"""


@app.get("/api/classes")
def classes(request: Request, x_demo_session: str | None = Header(default=None)):
    return REGISTRY.get(session_of(request, x_demo_session)).list_classes()


@app.get("/api/bookings")
def bookings(request: Request, x_demo_session: str | None = Header(default=None)):
    return REGISTRY.get(session_of(request, x_demo_session)).list_bookings()


@app.post("/api/bookings")
async def create(request: Request, x_demo_session: str | None = Header(default=None)):
    try:
        body = await request.json()
    except Exception:                                    # noqa: BLE001
        body = {}
    gym = REGISTRY.get(session_of(request, x_demo_session))
    result = gym.create_booking(str((body or {}).get("class_id", "")))
    return JSONResponse(result, status_code=200 if result.get("ok") else 400)


@app.delete("/api/bookings/{booking_id}")
def cancel(booking_id: str, request: Request,
           x_demo_session: str | None = Header(default=None)):
    """The vulnerable endpoint.

    No ownership check, exactly as the real one had none. Deliberate.
    """
    gym = REGISTRY.get(session_of(request, x_demo_session))
    result = gym.cancel_booking(booking_id)
    return JSONResponse(result, status_code=200 if result.get("ok") else 404)


@app.post("/api/reset")
def reset(request: Request, x_demo_session: str | None = Header(default=None)):
    """Back to the incident, which means the bookings AND the gate.

    The public gym is shared, so the previous visitor's UBAG toggle is still
    set when the next one arrives. Restoring the bookings while leaving
    enforcement armed produces a fresh gym that silently refuses the attack,
    which reads as a broken exhibit rather than a defended one. Reset is the
    button people press when something looks wrong, so it has to return the
    whole thing to the undefended state, not half of it.
    """
    session = session_of(request, x_demo_session)
    gym = REGISTRY.reset(session)
    gym_gate.disarm(session)
    return {"ok": True, "classes": gym.list_classes(), "bookings": gym.list_bookings(),
            "ubag_enabled": gym_gate.enforcement_enabled(session)}


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True, "sessions": REGISTRY.count(), "disclosure": DISCLOSURE,
            "ubag_available": gym_gate.GATE_AVAILABLE}


# ---------------------------------------------------------------------------
# UBAG, mounted last and switched off
#
# Last because middleware added later runs further out, and the gate has to sit
# outside the handlers it protects. Switched off because the broken handler is
# the exhibit: `gym.py` says so in its own docstring. A visitor turns it on with
# POST /api/ubag {"enabled": true} and runs the identical attack again.
#
# install() returns False when the commercial engine is not present in this
# image, and the gym then behaves exactly as it does today. That is the intended
# state for a public build: the exhibit must never depend on a private package
# being importable in order to stay up.
# ---------------------------------------------------------------------------
app.include_router(gym_gate.router)

UBAG_INSTALLED = gym_gate.install(
    app, session_of,
    always_headers={"X-Demo-Disclosure": DISCLOSURE,
                    "X-Robots-Tag": "noindex, nofollow"})
