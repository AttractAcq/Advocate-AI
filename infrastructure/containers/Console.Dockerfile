FROM docker.io/library/node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /workspace
COPY apps/console/web/package.json apps/console/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY apps/console/web/ ./
RUN npm run build

FROM docker.io/library/caddy:2-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
ENV XDG_CONFIG_HOME=/tmp/caddy/config XDG_DATA_HOME=/tmp/caddy/data
COPY infrastructure/containers/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /workspace/dist /srv
USER 10001:10001
EXPOSE 8080
