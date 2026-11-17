FROM docker.io/library/node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /workspace
COPY apps/fleet/web/package.json apps/fleet/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY apps/fleet/web/ ./
RUN npm run build

FROM docker.io/library/nginx:1.30.6-alpine-slim@sha256:e2355aa95529a7999dad94ddcb45a8768abf6fb0b204c93b1a3ffce477d7b893
COPY infrastructure/containers/fleet-nginx.conf /etc/nginx/nginx.conf
COPY --from=build /workspace/dist /srv
USER 10001:10001
EXPOSE 8080
