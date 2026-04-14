# ── Stage 1: build the React app ─────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Install deps first (cached layer)
COPY frontend/package*.json ./
RUN npm install --legacy-peer-deps

# Copy source and build
COPY frontend/ ./
RUN npm run build
# dist/ is now at /build/dist

# ── Stage 2: serve with nginx ─────────────────────────────────────────────────
FROM nginx:1.27-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# nginx docker image auto-runs envsubst on files in /etc/nginx/templates/
COPY docker/frontend/nginx.conf.template /etc/nginx/templates/default.conf.template

# Copy built assets
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 80

# Default backend URL (works for docker-compose; override with -e for standalone)
ENV BACKEND_URL=http://sentinel:8000

CMD ["nginx", "-g", "daemon off;"]
