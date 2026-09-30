# The intentionally vulnerable booking service.
#
#   THIS CONTAINER IS BROKEN ON PURPOSE.
#
# It reproduces the Melbourne gym incident of 10 August 2026: the cancellation
# endpoint performs no ownership check. That defect is the exhibit and it is not
# going to be fixed. Run it on its OWN host, never sharing a domain with anything
# real, so that a scanner or a passer-by cannot mistake it for an incident. Every
# response carries X-Demo-Disclosure and X-Robots-Tag: noindex.
#
# The image deliberately carries no part of UBAG. The gym is the thing being
# protected, not the thing protecting. The console reaches it over HTTP through
# the egress guard, and that is where the gate sits.
#
#   docker build -f ubag-mcp/demo/live/Dockerfile -t ubag-demo-gym .
#
# Copyright (c) 2026 Dixit Algorizmi Inc. PolyForm Noncommercial 1.0.0.

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY ubag-mcp/demo/live/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The booking service itself. gym_gate imports the engine inside a try/except
# and reports itself unavailable when it is absent, so this image cannot be
# armed at all.
COPY ubag-mcp/demo/live/gym.py         /app/gym.py
COPY ubag-mcp/demo/live/gym_service.py /app/gym_service.py
COPY ubag-mcp/demo/live/gym_gate.py    /app/gym_gate.py

ENV PORT=8080
EXPOSE 8080

# ---------------------------------------------------------------------------
# Default. Carries no engine, so /api/ubag reports unavailable and returns 503
# to any attempt to switch enforcement on. The attack succeeds, which is the
# entire point of this build.
# ---------------------------------------------------------------------------
FROM base AS defenceless

RUN useradd --create-home --uid 10001 demo && chown -R demo:demo /app
USER demo

# Shell form with `exec`, not JSON form: JSON does no variable expansion, so
# ${PORT} would reach uvicorn as a literal and Cloud Run would never get a
# listener. `exec` replaces the shell, so SIGTERM still reaches the server.
#
# One worker: bookings live in memory, keyed per visitor session, so a second
# worker would give the same visitor a different gym on every request. It is
# also why the enforcement toggle is correct as a process-local dict.
CMD exec uvicorn gym_service:app --host 0.0.0.0 --port ${PORT} --workers 1 \
    --no-access-log --log-level warning
