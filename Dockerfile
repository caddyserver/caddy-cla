FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /caddy-cla ./cmd/caddy-cla

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 cla
WORKDIR /app
COPY --from=build /caddy-cla /app/caddy-cla
COPY agreement.md /app/agreement.md
USER cla
EXPOSE 8080
ENTRYPOINT ["/app/caddy-cla"]
CMD ["-config", "/config/config.json"]
# Mount configuration read-only and a writable persistent /data directory.
# Set listen=0.0.0.0:8080 and database=/data/cla.db in that configuration.
