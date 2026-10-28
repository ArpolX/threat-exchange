FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o inf_threat ./cmd/app

FROM alpine:latest
COPY --from=builder /app/inf_threat /inf_threat
COPY --from=builder /app/migrations /migrations
CMD [ "/inf_threat" ]
