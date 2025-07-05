# Build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Download dependencies

COPY go.mod .
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -o collector

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/collector .

# Copy config
COPY config /config

# Expose syslog ports
EXPOSE 514/udp
EXPOSE 514/tcp

CMD ["./collector"]
