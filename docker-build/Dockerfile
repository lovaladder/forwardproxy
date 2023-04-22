FROM caddy:builder-alpine AS builder

RUN git clone --single-branch --branch=naive --depth=1 https://github.com/ghostGPT/forwardproxy.git /tmp/forwardproxy && \
    git clone --single-branch --branch=master --depth=1 https://github.com/mholt/caddy-grpc-web.git /tmp/grpc-web && \
    xcaddy build \
      --with github.com/caddyserver/forwardproxy=/tmp/forwardproxy \
      --with github.com/mholt/caddy-grpc-web=/tmp/grpc-web

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy