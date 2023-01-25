FROM python:3.7-alpine

# Copy the worker
COPY src /opt/opencti-connector-rcatt

# Install Python modules
# hadolint ignore=DL3003
RUN echo "http://dl-8.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
RUN apk --no-cache --update-cache add git build-base libmagic libffi-dev gcc gfortran build-base wget freetype-dev libpng-dev openblas-dev zlib-dev jpeg-dev libpng-dev && \
    ln -s /usr/include/locale.h /usr/include/xlocale.h && \
    cd /opt/opencti-connector-rcatt && \
    pip3 install --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

RUN python3 -m nltk.downloader punkt
RUN python3 -m nltk.downloader wordnet

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
