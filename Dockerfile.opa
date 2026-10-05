# Dockerfile.opa
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache curl jq

RUN curl -L -o /tmp/opa https://openpolicyagent.org/downloads/v1.20.2/opa_linux_amd64_static && \
    chmod 755 /tmp/opa && \
    mv /tmp/opa /usr/local/bin/opa

RUN curl -L -o /tmp/regal https://github.com/StyraInc/regal/releases/download/v0.42.0/regal_Linux_x86_64 && \
    chmod 755 /tmp/regal && \
    mv /tmp/regal /usr/local/bin/regal

EXPOSE 8181

COPY . /
