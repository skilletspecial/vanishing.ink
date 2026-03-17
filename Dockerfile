FROM oven/bun:1-alpine AS base
WORKDIR /app

# Install dependencies in a separate layer for better cache reuse
COPY package.json ./
RUN bun install --production --ignore-scripts

COPY server/ ./server/
COPY public/ ./public/

# ONCE mounts a persistent volume at /storage; create it here so it
# exists even when the volume is not mounted (e.g. local development).
RUN mkdir -p /storage && chown bun:bun /storage

# ONCE backup/restore hooks (optional but recommended for data safety)
COPY hooks/ /hooks/
RUN chmod +x /hooks/pre-backup /hooks/post-restore

EXPOSE 80

USER bun
CMD ["bun", "run", "server/index.ts"]
