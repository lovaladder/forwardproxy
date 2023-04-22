FROM caddy:builder-alpine AS builder

RUN xcaddy build \
    --with github.com/caddyserver/forwardproxy@caddy2=github.com/ghostGPT/forwardproxy@naive \
    --with github.com/mholt/caddy-grpc-web@master=github.com/ghostGPT/caddy-grpc-web@master

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy