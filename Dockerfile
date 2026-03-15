# syntax=docker/dockerfile:1.6

FROM golang:1.23 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN mkdir -p /out/updates

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/tmp/go-tmp \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTMPDIR=/tmp/go-tmp \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /out/updates/intratun-linux-amd64 ./cmd/intratun

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/tmp/go-tmp \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTMPDIR=/tmp/go-tmp \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -ldflags "-s -w" -o /out/updates/intratun-linux-arm64 ./cmd/intratun

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/tmp/go-tmp \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTMPDIR=/tmp/go-tmp \
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
    go build -trimpath -ldflags "-s -w" -o /out/updates/intratun-darwin-arm64 ./cmd/intratun

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/tmp/go-tmp \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTMPDIR=/tmp/go-tmp \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /out/updates/intratun-windows-amd64.exe ./cmd/intratun

RUN cd /out/updates && sha256sum intratun-* > SHA256SUMS

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/tmp/go-tmp \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTMPDIR=/tmp/go-tmp \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/intratun ./cmd/intratun

FROM busybox:1.36.1 AS runtime-prep

RUN mkdir -p /var/lib/intratun/acme /var/lib/intratun/updates \
    && touch /var/lib/intratun/acme/.keep \
    && touch /var/lib/intratun/updates/.keep \
    && chmod 700 /var/lib/intratun/acme \
    && chmod 755 /var/lib/intratun/updates \
    && chown -R 65532:65532 /var/lib/intratun

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=runtime-prep /var/lib/intratun /var/lib/intratun
COPY --from=build /out/intratun /usr/local/bin/intratun
COPY --from=build --chown=nonroot:nonroot /out/updates/ /var/lib/intratun/updates/

ENTRYPOINT ["/usr/local/bin/intratun"]
# Default to showing help; override in docker run / compose.
CMD ["--help"]
