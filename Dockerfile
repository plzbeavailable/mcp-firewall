# ─── Build stage ─────────────────────────────────────────────
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /build

COPY pnpm-workspace.yaml package.json turbo.json tsconfig.base.json ./
COPY packages/config/package.json packages/config/
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/dashboard-api/package.json packages/dashboard-api/
COPY apps/proxy/package.json apps/proxy/

RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm run build

# ─── Runtime stage ───────────────────────────────────────────
FROM node:22-alpine

RUN addgroup -S mcp-firewall && adduser -S mcp-firewall -G mcp-firewall

WORKDIR /app

# Copy built artifacts
COPY --from=builder /build/node_modules/.pnpm ./node_modules/.pnpm
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package.json ./package.json
COPY --from=builder /build/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=builder /build/packages/config/dist ./packages/config/dist
COPY --from=builder /build/packages/config/package.json ./packages/config/package.json
COPY --from=builder /build/packages/core/dist ./packages/core/dist
COPY --from=builder /build/packages/core/package.json ./packages/core/package.json
COPY --from=builder /build/packages/db/dist ./packages/db/dist
COPY --from=builder /build/packages/db/package.json ./packages/db/package.json
COPY --from=builder /build/packages/dashboard-api/dist ./packages/dashboard-api/dist
COPY --from=builder /build/packages/dashboard-api/package.json ./packages/dashboard-api/package.json
COPY --from=builder /build/apps/proxy/dist ./apps/proxy/dist
COPY --from=builder /build/apps/proxy/package.json ./apps/proxy/package.json

RUN mkdir -p /app/data && chown -R mcp-firewall:mcp-firewall /app

USER mcp-firewall

ENV NODE_ENV=production

# Default args — overridden by docker-compose
ENTRYPOINT ["node", "apps/proxy/dist/index.js", "run"]
CMD ["/app/mcp-firewall.yaml"]
