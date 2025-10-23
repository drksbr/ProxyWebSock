# syntax=docker/dockerfile:1.6

FROM golang:1.23 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "-s -w" -o /out/intratun ./cmd/intratun

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/intratun /usr/local/bin/intratun

ENTRYPOINT ["/usr/local/bin/intratun"]
# Default to showing help; override in docker run / compose.
CMD ["--help"]
