# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.8
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/aegissre ./cmd/aegissre

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="AegisSRE" \
      org.opencontainers.image.description="Constrained autonomous reliability agents" \
      org.opencontainers.image.source="https://github.com/shanurwan/AegisSRE"

COPY --from=build --chown=65532:65532 /out/aegissre /usr/local/bin/aegissre

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegissre"]
