# Click Shield dashboard: build the Vite app, serve it with nginx.
# nginx also proxies /api/* to the backend, so the SPA keeps calling the
# relative /api/v1 base URL (src/lib/api.ts) in every environment.

# ---- Build ----
FROM node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- Serve ----
FROM nginx:1.27-alpine

# Rendered by the nginx image at startup with envsubst (only defined env vars are replaced).
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

# Where /api/* is proxied. docker-compose: the `backend` service.
# AWS: the API's internal address — or route /api/* at the ALB and never hit this proxy.
ENV BACKEND_UPSTREAM=http://backend:8000

EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1
