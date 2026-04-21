FROM caddy:2.11-builder AS builder
COPY bodylogger /src/bodylogger
RUN xcaddy build \
    --with github.com/caddyserver/replace-response \
    --with github.com/lab/bodylogger=/src/bodylogger

FROM caddy:2.11-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
