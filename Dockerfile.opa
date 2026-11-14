# Dockerfile.opa
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache curl jq

RUN curl -L -o /tmp/opa https://openpolicyagent.org/downloads/v1.20.2/opa_linux_amd64_static && \
    chmod 755 /tmp/opa && \
    mv /tmp/opa /usr/local/bin/opa

RUN curl -L -o /tmp/regal https://github.com/StyraInc/regal/releases/download/v0.43.0/regal_Linux_x86_64 && \
    chmod 755 /tmp/regal && \
    mv /tmp/regal /usr/local/bin/regal

EXPOSE 8181

COPY . /
