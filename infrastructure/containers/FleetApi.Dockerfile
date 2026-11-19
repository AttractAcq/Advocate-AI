# Separate company-side synthetic Fleet service; excluded from the vessel image.
FROM docker.io/library/python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/sovereign
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip uninstall -y pip \
    && adduser -D -u 10001 sovereign
COPY apps/__init__.py ./apps/__init__.py
COPY apps/api/__init__.py apps/api/oidc.py ./apps/api/
COPY apps/fleet ./apps/fleet
COPY services/__init__.py ./services/__init__.py
COPY services/fleet ./services/fleet
USER 10001:10001
EXPOSE 18800
CMD ["python", "-m", "uvicorn", "apps.fleet.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "18800", "--no-server-header"]
