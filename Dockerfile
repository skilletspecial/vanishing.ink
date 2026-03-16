FROM oven/bun:1-alpine AS base
WORKDIR /app

# Install dependencies in a separate layer for better cache reuse
COPY package.json ./
RUN bun install --production

COPY server/ ./server/
COPY public/ ./public/

EXPOSE 3000

USER bun
CMD ["bun", "run", "server/index.ts"]
