FROM docker-proxy.mirror.queen.zoo/python:3.10-alpine

RUN  echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/main" > /etc/apk/repositories && \
     echo "http://mirror.queen.zoo./artifactory/dl-cdn-alpinelinux-org/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories && \
     apk update

# Copy confs
COPY pip.conf /root/.config/pip/pip.conf
COPY netrc /root/.netrc

# Copy the worker
COPY internal-export-file/export-report-pdf/src /opt/opencti-connector-export-report-pdf

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev zlib-dev tiff-dev jpeg-dev openjpeg-dev zlib-dev \
    freetype-dev lcms2-dev libwebp-dev tcl-dev tk-dev harfbuzz-dev fribidi-dev libimagequant-dev \
    libxcb-dev libpng-dev pango weasyprint && \
    git config --global http.sslVerify false && \
    cd /opt/opencti-connector-export-report-pdf && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY internal-export-file/export-report-pdf/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
