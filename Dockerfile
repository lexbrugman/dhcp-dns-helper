FROM python:3.14-slim-bookworm@sha256:8e729c1805fb85b93e435f6c0ba67069e1b2cfd1ce4f72a9481f6a737434b46b

ARG GIT_SHA
# Only what a build off a checkout carries: CI passes the version it resolved,
# and the labels docker/metadata-action attaches overwrite both of these
# anyway. A local build is a dev build and says so.
ARG VERSION=dev
LABEL org.opencontainers.image.title="dhcp-dns-helper"
LABEL org.opencontainers.image.description="HTTP wrapper around nsupdate for DHCP lease DNS updates"
LABEL org.opencontainers.image.source="https://github.com/lexbrugman/dhcp-dns-helper"
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

RUN addgroup --system --gid 10001 app \
    && adduser --system --uid 10001 --ingroup app --home /app app

WORKDIR /app

COPY src/requirements.txt /app/src/requirements.txt
RUN pip install --no-cache-dir -r /app/src/requirements.txt

COPY src /app/src
RUN chown -R app:app /app

USER app
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "dhcp_dns_helper.app:app"]
