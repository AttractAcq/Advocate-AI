# Synthetic lab image. The release candidate workflow must rescan the resolved image.
FROM docker.io/library/python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/sovereign
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY apps/api ./apps/api
COPY services ./services
COPY fixtures ./fixtures
RUN python fixtures/generate.py && adduser -D -u 10001 sovereign
USER 10001:10001
EXPOSE 18100
CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "18100", "--no-server-header"]
