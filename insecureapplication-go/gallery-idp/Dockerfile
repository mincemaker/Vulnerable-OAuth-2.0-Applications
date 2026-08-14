# syntax=docker/dockerfile:1
# check=error=true

FROM golang:1.26-alpine AS builder
WORKDIR /app

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download

COPY . .

# modernc.org/sqlite is pure Go, so CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod/ \
    CGO_ENABLED=0 go build -ldflags="-s" -trimpath -o /bin/gallery-idp ./cmd/gallery-idp

FROM alpine:3.20
WORKDIR /app

COPY --from=builder /bin/gallery-idp /app/gallery-idp
# web/static and the two seed photos are compiled into the binary via
# go:embed (see web/embed.go and db/seedfiles.go); the binary writes the
# seed photos out to -uploads on startup, so nothing else needs COPYing.

EXPOSE 3005

ENTRYPOINT ["/app/gallery-idp"]
CMD ["-listen", ":3005", "-db", "/app/gallery-idp.sqlite3", "-uploads", "/app/public/uploads"]
