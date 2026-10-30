# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG GO_VERSION=1.26.10
# Keep GO_VERSION and this digest in lockstep. The digest makes the build input
# immutable even if the upstream convenience tag moves.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

LABEL org.opencontainers.image.title="AegisSRE" \
      org.opencontainers.image.description="Constrained autonomous reliability agents" \
      org.opencontainers.image.source="https://github.com/shanurwan/AegisSRE"

COPY --from=build --chown=65532:65532 /out/aegissre /usr/local/bin/aegissre

USER 65532:65532
EXPOSE 8080 8443 9090
ENTRYPOINT ["/usr/local/bin/aegissre"]
