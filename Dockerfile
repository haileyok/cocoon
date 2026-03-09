### Compile stage
FROM golang:1.26.1-bookworm AS build-env

WORKDIR /dockerbuild
ADD . .

RUN GIT_VERSION=$(git describe --tags --long --always || echo "dev-local") && \
    go mod tidy && \
    go build -ldflags "-X main.Version=$GIT_VERSION" -o cocoon ./cmd/cocoon

### Run stage
FROM debian:bookworm-slim AS run

RUN apt-get update && apt-get install -y dumb-init runit ca-certificates curl && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["dumb-init", "--"]

WORKDIR /
RUN mkdir -p data/cocoon
COPY --from=build-env /dockerbuild/cocoon /

COPY ./init-keys.sh /
COPY ./create-initial-invite.sh /

CMD ["/cocoon", "run"]

LABEL org.opencontainers.image.source=https://github.com/haileyok/cocoon
LABEL org.opencontainers.image.description="Cocoon ATProto PDS"
LABEL org.opencontainers.image.licenses=MIT
