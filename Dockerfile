FROM python:3.13-slim
RUN useradd --uid 1000 --create-home sift
COPY sift.py /app/sift.py
COPY web /app/web
COPY agents /app/agents
USER sift
WORKDIR /app
ENV PYTHONUNBUFFERED=1
# config.json (with the secrets) + sift.db live in the mounted /data volume,
# so nothing secret is baked into the image.
CMD ["python", "sift.py", "/data/config.json"]
