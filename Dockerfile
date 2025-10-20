FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/intratun .

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/intratun /usr/local/bin/intratun
ENTRYPOINT ["/usr/local/bin/intratun"]
