# Dockerfile.opa
FROM alpine:3.22.1

RUN apk add --no-cache curl jq

RUN curl -L -o /tmp/opa https://openpolicyagent.org/downloads/v1.2.0/opa_linux_amd64_static && \
    chmod 755 /tmp/opa && \
    mv /tmp/opa /usr/local/bin/opa

RUN curl -L -o /tmp/regal https://github.com/StyraInc/regal/releases/download/v0.31.1/regal_Linux_x86_64 && \
    chmod 755 /tmp/regal && \
    mv /tmp/regal /usr/local/bin/regal

EXPOSE 8181

COPY . /
