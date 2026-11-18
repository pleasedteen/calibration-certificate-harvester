FROM python:3.12-slim

WORKDIR /app
COPY certcollector /app/certcollector
COPY pyproject.toml README.md /app/

ENV CERTCOLLECTOR_DATA_DIR=/data
ENV CERTCOLLECTOR_DATABASE_URL=sqlite:////data/certcollector.db
VOLUME ["/data"]
EXPOSE 8000

# For PostgreSQL instead:
#   docker run -e CERTCOLLECTOR_DATABASE_URL=postgresql://... -p 8000:8000 <image>
CMD ["python3", "-m", "certcollector", "--host", "0.0.0.0", "--port", "8000"]
