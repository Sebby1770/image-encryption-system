# syntax=docker/dockerfile:1

# Build the wheel in a throwaway stage so the runtime image carries neither the
# build toolchain nor the source tree.
FROM python:3.12-slim AS build

WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist


FROM python:3.12-slim AS runtime

# Pillow and cryptography ship manylinux wheels, so no compiler is needed here.
RUN adduser --system --group --home /app vault
WORKDIR /app

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl gunicorn && rm /tmp/*.whl

# The vault database, ciphertext, encrypted private keys, and the generated
# signing secret all live here. Mount a volume over it or every restart starts
# an empty vault.
ENV IES_INSTANCE_DIR=/data
RUN mkdir -p /data && chown vault:vault /data
VOLUME ["/data"]

USER vault
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

# Scrypt holds ~67 MB per in-flight decrypt, so keep the worker count modest and
# let the container's memory limit be the real bound.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", \
     "--timeout", "120", "image_encryption_system.web:create_app()"]
