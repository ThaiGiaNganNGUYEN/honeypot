FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HONEYPOT_DROP_PRIVILEGES=1

WORKDIR /app

RUN useradd --system --create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /app/logs /app/keys \
    && chown honeypot:honeypot /app/logs /app/keys

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config ./config
COPY honeypot ./honeypot

EXPOSE 2222 8080 2121 8090

# Starts as root so a mounted log directory can be made writable, then drops
# to the honeypot user when the platform allows it.
CMD ["python", "-m", "honeypot", "--bind", "0.0.0.0", "--dashboard-bind", "0.0.0.0"]
