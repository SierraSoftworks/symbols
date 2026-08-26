# NOTE: This Dockerfile depends on you building the symbols binary first.
# It will then package that binary into the image, and use that as the
# entrypoint. This mirrors the grey build model: `docker build` is not a
# repeatable way to build the same image, but cross-platform builds are much
# faster; a net win.
FROM ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/SierraSoftworks/symbols
LABEL org.opencontainers.image.description="Self-hosted debug symbol server speaking the debuginfod protocol"

RUN apt-get update && apt-get install -y \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ADD ./symbols /usr/local/bin/symbols

ENTRYPOINT ["/usr/local/bin/symbols"]
