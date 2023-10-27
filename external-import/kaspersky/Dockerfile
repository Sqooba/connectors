# The base image.
FROM docker-proxy.mirror.queen.zoo/python:3.11-alpine as base

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf

# Copy the connector
COPY external-import/kaspersky/src /opt/opencti-connector-kaspersky

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    git config --global http.sslVerify false && \
    cd /opt/opencti-connector-kaspersky && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY external-import/kaspersky/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

