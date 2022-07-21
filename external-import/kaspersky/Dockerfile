# The base image.
FROM docker-proxy.mirror.queen.zoo/python:3.10-alpine

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf
COPY netrc /root/.netrc

# Copy the source and set the working directory.
COPY external-import/kaspersky/src /opt/opencti-connector-kaspersky

# Install OS dependencies.
RUN apk update && \
    apk --no-cache add build-base git libxml2-dev libxslt-dev libmagic libxml2 libxslt && \
    git config --global http.sslVerify false && \
    cd /opt/opencti-connector-kaspersky && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Entrypoint.
COPY external-import/kaspersky/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
