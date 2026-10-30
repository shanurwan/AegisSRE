# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Instrumented test build for IAST. Same sources as the release image, built
# with the race detector and coverage counters. Never published or deployed:
# -race needs cgo and glibc, so it cannot use the distroless static runtime.
ARG GO_VERSION=1.26.10
FROM golang:${GO_VERSION}-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -buildvcs=false -race \
    -cover -covermode=atomic -coverpkg=./... \
    -o /out/aegissre ./cmd/aegissre

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

COPY --from=build /out/aegissre /usr/local/bin/aegissre

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aegissre"]
