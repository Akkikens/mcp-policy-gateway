# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Akkikens/mcp-policy-gateway/internal/gateway.Version=${VERSION}" -o /out/mcpgw ./cmd/mcpgw

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcpgw /mcpgw
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mcpgw"]
CMD ["serve", "-config", "/etc/mcpgw/gateway.json"]
