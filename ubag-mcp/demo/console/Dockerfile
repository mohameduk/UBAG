# The UBAG demonstration console, for any container host.
#
# Build context is the ROOT of the ubag repository, because the console runs
# the real ubag-core and ubag-mcp rather than a vendored copy.
# The whole point of the demo is that the verdicts come from the shipping
# engine, so the container has to carry that engine and not a stand-in.
#
#   git clone https://github.com/mohameduk/ubag && cd ubag
#   docker build -f ubag-mcp/demo/console/Dockerfile -t ubag-console .
#
# Copyright (c) 2026 Dixit Algorizmi Inc. PolyForm Noncommercial 1.0.0.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY ubag-mcp/demo/console/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The engine, and the MCP surface with both demos inside it. The web-layer
# tab needs UBAG Edge, which is not in this release, so the console hides it.
COPY ubag-core/ /app/ubag-core/
COPY ubag-mcp/  /app/ubag-mcp/

WORKDIR /app/ubag-mcp/demo/console
ENV PYTHONPATH=/app/ubag-core:/app/ubag-mcp:/app/ubag-mcp/demo/console:/app/ubag-mcp/demo/live

# Not root. A public endpoint that runs a language model's suggestions has no
# business holding more privilege than it needs, even inside a container.
RUN useradd --create-home --uid 10001 demo && chown -R demo:demo /app
USER demo

# The host supplies $PORT (Cloud Run, Fly, Render all do). Fixed at one worker on purpose: the console holds
# session state in memory and the rate limiter counts per process, so a second
# worker would silently double the spend ceiling. Run a single instance.
ENV PORT=8080
EXPOSE 8080
# Shell form with `exec`, not JSON form, and the buildkit lint warning about
# that is wrong here. JSON form does no variable expansion, so ${PORT} would
# reach uvicorn as a literal string and Cloud Run would never get a listener on
# the port it assigned. `exec` replaces the shell with uvicorn, so SIGTERM still
# arrives at the server: measured, `docker stop` returns in under a second
# rather than waiting out the 10 second kill timeout.
#
# --no-proxy-headers is load-bearing, not tidiness. With uvicorn's default
# (proxy headers ON) uvicorn rewrites request.client from X-Forwarded-For before
# any application code runs, which lets a direct caller pick their own identity
# and so their own rate-limit bucket. Whether that header is believed is decided
# in limits.TRUST_PROXY and nowhere else.
CMD exec uvicorn asgi:app --host 0.0.0.0 --port ${PORT} --workers 1 \
    --no-proxy-headers --no-access-log --log-level warning
