FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG GIT_SHA
LABEL org.opencontainers.image.title="dhcp-dns-helper"
LABEL org.opencontainers.image.description="HTTP wrapper around nsupdate for DHCP lease DNS updates"
LABEL org.opencontainers.image.source="https://github.com/lexbrugman/dhcp-dns-helper"
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.version="${GIT_SHA}"

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
