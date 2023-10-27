FROM docker-proxy.mirror.queen.zoo/python:3.11-alpine

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf

# Copy the connector
COPY external-import/valhalla/src /opt/opencti-connector-valhalla

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    git config --global http.sslVerify false && \
    cd /opt/opencti-connector-valhalla && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY external-import/valhalla/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
