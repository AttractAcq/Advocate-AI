# Synthetic lab image. The release candidate workflow must rescan the resolved image.
FROM docker.io/library/python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/sovereign
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY apps/api ./apps/api
COPY services ./services
COPY fixtures ./fixtures
RUN python fixtures/generate.py && useradd --system --uid 10001 --no-create-home sovereign
USER 10001:10001
EXPOSE 18100
CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "18100", "--no-server-header"]
