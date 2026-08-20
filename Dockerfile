FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md requirements.txt ./
COPY src ./src
COPY run.py ./run.py

RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 vault \
    && mkdir -p /data \
    && chown -R vault:vault /app /data

USER vault
ENV PYTHONPATH=/app/src
ENV IES_INSTANCE_DIR=/data
ENV IES_HOST=0.0.0.0
ENV IES_PORT=5000

EXPOSE 5000
VOLUME ["/data"]

CMD ["python", "run.py"]
