FROM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sysbridge-mcp ./cmd/sysbridge-mcp

FROM alpine:3.20

RUN apk add --no-cache ca-certificates openssh-client mosh-client && \
    addgroup -S sysbridge && \
    adduser -S -G sysbridge -h /home/sysbridge sysbridge

USER sysbridge
WORKDIR /home/sysbridge

COPY --from=builder /out/sysbridge-mcp /usr/local/bin/sysbridge-mcp

EXPOSE 8080/tcp
EXPOSE 42424/udp

ENTRYPOINT ["/usr/local/bin/sysbridge-mcp"]
CMD ["--transport", "stdio"]
