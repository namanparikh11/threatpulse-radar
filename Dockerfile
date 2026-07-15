# V6.2 — ThreatPulse Radar portable Docker image.
#
# The image runs the V6.2 portable HTTP server on port
# 8787 plus the CLI jobs as one-shot commands. It is
# OPTIONAL — the application runs without Docker on
# Netlify, local Node, and Hostinger Business. Docker
# is supported for the future VPS / container platform
# scenario.
#
# Build:
#   docker build -t threatpulse-radar:v6-2 .
#
# Run (HTTP server):
#   docker run --rm -p 8787:8787 \
#     -e THREATPULSE_STORAGE_BACKEND=filesystem \
#     -e THREATPULSE_DATA_ROOT=/var/lib/threatpulse/state \
#     -v threatpulse-state:/var/lib/threatpulse/state \
#     threatpulse-radar:v6-2 \
#     node server/http.mjs
#
# Run (CLI job):
#   docker run --rm \
#     -e THREATPULSE_STORAGE_BACKEND=filesystem \
#     -e THREATPULSE_DATA_ROOT=/var/lib/threatpulse/state \
#     -v threatpulse-state:/var/lib/threatpulse/state \
#     threatpulse-radar:v6-2 \
#     node jobs/verify-state.mjs

FROM node:24-alpine

# Create a non-root user for the runtime.
RUN addgroup -S threatpulse && adduser -S threatpulse -G threatpulse

WORKDIR /app

# Copy package files first for better layer caching.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# Copy the rest of the application.
COPY --chown=threatpulse:threatpulse . /app

# Persistent data volume. The Hostinger / VPS / Docker
# deployment mounts a real volume here. In a local
# test run, the image uses a tmpfs mount.
RUN mkdir -p /var/lib/threatpulse/state && \
    chown -R threatpulse:threatpulse /var/lib/threatpulse

USER threatpulse

ENV THREATPULSE_STORAGE_BACKEND=filesystem \
    THREATPULSE_DATA_ROOT=/var/lib/threatpulse/state \
    THREATPULSE_HTTP_HOST=0.0.0.0 \
    THREATPULSE_HTTP_PORT=8787 \
    NODE_ENV=production

EXPOSE 8787

# Health check against the portable HTTP server.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8787/health >/dev/null 2>&1 || exit 1

# Default command: run the portable HTTP server.
CMD ["node", "server/http.mjs"]
