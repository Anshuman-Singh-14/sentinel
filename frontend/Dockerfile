# syntax=docker/dockerfile:1
# Targets:
#   dev   Vite dev server, used by docker compose (node:24-alpine, runs as `node`)
#   prod  static build served by unprivileged nginx (production profile)

FROM node:24-alpine AS deps
WORKDIR /app
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM deps AS dev
COPY --chown=node:node . .
EXPOSE 5173
CMD ["npm", "run", "dev"]

FROM deps AS build
COPY --chown=node:node . .
RUN npm run build

# nginx-unprivileged is the official NGINX image variant that runs as a non-root
# user and listens on 8080, so no capabilities are needed (04-security.md section 10).
FROM nginxinc/nginx-unprivileged:1.29-alpine AS prod
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
