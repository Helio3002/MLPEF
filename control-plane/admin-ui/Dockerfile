# MLPEF admin-ui image: build the Vite/React SPA, serve the static bundle via nginx.
# Build context is this directory (control-plane/admin-ui).
# syntax=docker/dockerfile:1

# --- build stage ---------------------------------------------------------- #
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json* ./
# Prefer a reproducible `npm ci`; fall back to `npm install` when there is no
# lockfile or it is out of sync with package.json (keeps the demo build robust).
RUN npm ci || npm install

COPY . .

# Vite inlines VITE_* at BUILD time, so the API base URL is baked into the bundle.
# It must be the URL the *browser* uses to reach the control-api (not the docker
# network name). Override per environment (e.g. a Codespaces forwarded URL).
ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

# --- serve stage ---------------------------------------------------------- #
FROM nginx:1.27-alpine AS serve
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
