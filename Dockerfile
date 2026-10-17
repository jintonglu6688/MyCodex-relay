# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
    -ldflags="-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=${VERSION}" \
    -o /out/mycodex-relay ./cmd/mycodex-relay

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="MyCodex Relay" \
      org.opencontainers.image.description="Relay service for MyCodex remote connections" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 relay \
    && adduser -S -D -H -u 10001 -G relay relay \
    && install -d -o relay -g relay /var/lib/mycodex-relay

COPY --from=build --chown=relay:relay /out/mycodex-relay /usr/local/bin/mycodex-relay

USER relay:relay
WORKDIR /var/lib/mycodex-relay

EXPOSE 38443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-T", "3", "-O", "/dev/null", "http://127.0.0.1:38443/health"]

ENTRYPOINT ["/usr/local/bin/mycodex-relay"]
CMD ["serve", "--config", "/etc/mycodex-relay/relay-config.json"]
