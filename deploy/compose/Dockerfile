# One image with every Kairan binary (Q-01). Build context: the repository root.
#   docker build -f deploy/compose/Dockerfile -t kairan:demo .
# Pinned base images (stdlib only, no module downloads). Dockerfile.dockerignore keeps
# the context to go.mod plus the Go sources.
FROM golang:1.25.14-alpine3.24 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
COPY . .
# -o with a directory writes one binary per main package:
# kairan-cp kairan-proxy kairanctl fakemcp kairan-sim.
RUN mkdir /out && go build -ldflags='-s -w' -o /out/ ./... && ls /out

FROM alpine:3.24.1
# Non-root user; every binary is on PATH. Data lives in volumes mounted by compose.
RUN adduser -D -H -u 10001 kairan && mkdir -p /data && chown kairan /data
COPY --from=build /out/ /usr/local/bin/
USER 10001:10001
WORKDIR /data
LABEL org.opencontainers.image.title="kairan demo (not for production)"
