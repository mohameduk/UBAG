"""
The deployed surface: the console as an ASGI app, for Cloud Run.

`server.py` keeps a dependency-free stdlib server for local development. This is
the same routing (`server.dispatch_get` / `server.dispatch_post`, one
implementation, two transports) with the things a public endpoint needs and a
laptop does not: `0.0.0.0:$PORT`, rate limiting, a spend ceiling, security
headers, and a health check the platform can poll.

Run:
    uvicorn asgi:app --host 0.0.0.0 --port 8765
    python asgi.py                       # reads $PORT, defaults to 8080

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import json
import os

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

import limits
import server

MAX_BODY_BYTES = 256_000

# A demo is not a place to accept cross-origin traffic. There is no CORS
# middleware here on purpose: the page and the API are same-origin, so adding
# one would only widen who can spend the model budget.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Guard(BaseHTTPMiddleware):
    """Rate limiting and security headers, in front of everything."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path not in ("/health",):
            client = limits.client_key(request.headers,
                                       request.client.host if request.client else "")
            check = (limits.LIMITER.check_model if path in server.MODEL_ROUTES
                     else limits.LIMITER.check_api)
            verdict = check(client)
            if not verdict.allowed:
                return JSONResponse(verdict.to_dict(), status_code=429,
                                    headers={"Retry-After": str(verdict.retry_after),
                                             **SECURITY_HEADERS})
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


async def index(request: Request):
    return HTMLResponse(server.console_html())


async def get_route(request: Request):
    try:
        return JSONResponse(server.dispatch_get(request.url.path))
    except KeyError:
        return PlainTextResponse("not found", status_code=404)


async def post_route(request: Request):
    path = request.url.path
    if path not in server.POST_ROUTES:
        return PlainTextResponse("not found", status_code=404)

    body = await request.body()
    if not body or len(body) > MAX_BODY_BYTES:
        return JSONResponse({"error": "bad request body"}, status_code=400)
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        result = server.dispatch_post(path, payload)
    except KeyError as exc:
        return JSONResponse({"error": f"unknown scenario {exc}"}, status_code=404)
    except Exception as exc:                                      # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(result)


async def healthz(request: Request):
    """Liveness plus the current spend position, so the ceiling is observable."""
    return JSONResponse({"ok": True, "limits": limits.LIMITER.describe()})


app = Starlette(
    routes=[Route("/", index), Route("/index.html", index),
            Route("/health", healthz),
            *[Route(path, get_route) for path in server.GET_ROUTES],
            *[Route(path, post_route, methods=["POST"]) for path in server.POST_ROUTES]],
    middleware=[Middleware(Guard)],
)


if __name__ == "__main__":
    import uvicorn
    # Cloud Run supplies $PORT and expects the process to bind it on 0.0.0.0.
    #
    # proxy_headers=False is load-bearing. Uvicorn turns it ON by default, and
    # when it is on uvicorn rewrites `request.client` from `X-Forwarded-For`
    # before any application code runs. That silently hands a direct caller the
    # ability to choose their own identity, which is exactly what the rate
    # limiter must not allow. Whether that header is believed is decided in one
    # place, `limits.TRUST_PROXY`, and it is not this one.
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")),
                proxy_headers=False, log_level="warning", access_log=False)
