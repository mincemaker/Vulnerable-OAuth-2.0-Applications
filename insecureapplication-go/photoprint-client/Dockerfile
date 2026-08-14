# syntax=docker/dockerfile:1
# check=error=true

FROM golang:1.26-alpine AS builder
WORKDIR /app

# no third-party dependencies (stdlib only), so there is no go.sum to
# download against -- COPY + build directly.
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod/ \
    CGO_ENABLED=0 go build -ldflags="-s" -trimpath -o /bin/photoprint-client ./cmd/photoprint-client

FROM alpine:3.20
WORKDIR /app

# web/static is compiled into the binary via go:embed (see web/embed.go),
# so nothing besides the binary itself needs to be copied here.
COPY --from=builder /bin/photoprint-client /app/photoprint-client

EXPOSE 3000

ENTRYPOINT ["/app/photoprint-client"]
CMD ["-listen", ":3000"]
