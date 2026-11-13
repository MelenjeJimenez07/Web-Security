# =============================================================================
# WebSec Audit Dashboard - Frontend Multi-Stage Dockerfile
# =============================================================================

FROM node:20-alpine AS build

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build


# -----------------------------------------------------------------------------
# Production Runtime: Unprivileged Nginx (non-root UID 101, port 8080)
# -----------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.27-alpine AS prod

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
