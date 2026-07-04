FROM golang:1.26-alpine AS builder

ARG VERSION=dev
WORKDIR /app

# Download deps first (cache layer)
COPY go.mod go.sum ./
RUN go mod download

# Build headscale
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o headscale \
    ./cmd/headscale

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/headscale /usr/local/bin/headscale

EXPOSE 8080 9090 50443

ENTRYPOINT ["headscale"]
