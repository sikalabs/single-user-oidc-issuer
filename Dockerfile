FROM golang:1.26 AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build

FROM debian:13-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/single-user-oidc-issuer /usr/local/bin/single-user-oidc-issuer
CMD ["/usr/local/bin/single-user-oidc-issuer", "server"]
EXPOSE 8080
