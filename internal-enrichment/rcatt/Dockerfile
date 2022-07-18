FROM sqooba-docker-dev.repo.king.zoo/python:3.7-alpine-rcatt-deps

# Copy the worker
COPY src /opt/opencti-connector-rcatt

# Install Python modules
# hadolint ignore=DL3003
RUN cd /opt/opencti-connector-rcatt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
