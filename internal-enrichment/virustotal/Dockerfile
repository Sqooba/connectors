FROM docker-proxy.mirror.queen.zoo/python:3.10-alpine

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf
COPY netrc /root/.netrc

# Copy the worker
COPY internal-enrichment/virustotal/src /opt/opencti-connector-virustotal

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    git config --global http.sslVerify false && \
    cd /opt/opencti-connector-virustotal && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY internal-enrichment/virustotal/entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
