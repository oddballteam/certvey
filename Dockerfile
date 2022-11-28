FROM golang:alpine AS builder
WORKDIR /app
RUN apk update && apk add --no-cache ca-certificates
COPY . .
RUN CGO_ENABLED=0 go build -a -o /app/certvey main.go

FROM scratch
COPY --from=builder /app/certvey /bin/certvey
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/bin/certvey"]