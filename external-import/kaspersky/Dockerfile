# The base image.
FROM docker-proxy.mirror.queen.zoo/python:3.11-alpine as base

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf
COPY netrc /root/.netrc

# The Builder.
FROM base as builder

# Set the working directory.
WORKDIR /builder

# Install OS dependencies.
RUN apk update && \
    apk --no-cache add build-base git libxml2-dev libxslt-dev && \
    rm -rf /var/cache/apk/*

# Setup the virtual environment.
RUN python -m venv /venv && \
    git config --global http.sslVerify false && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install wheel

# Install Python dependencies.
COPY external-import/kaspersky/src/requirements.txt ./
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt


# The Connector.
FROM base

# Copy the source and set the working directory.
COPY external-import/kaspersky/src /opt/opencti-connector-kaspersky
WORKDIR /opt/opencti-connector-kaspersky

# Install OS dependencies.
RUN apk update && \
    apk --no-cache add libmagic libxml2 libxslt && \
    rm -rf /var/cache/apk/*

# Copy the venv from the builder.
COPY --from=builder /venv /venv

# Entrypoint.
COPY external-import/kaspersky/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
