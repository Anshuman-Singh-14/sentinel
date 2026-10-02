# Lab banner server (compose profile "lab"). Standard library only, non-root.
FROM python:3.12-slim
RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin lab
COPY banner_server.py /srv/banner_server.py
USER 10002:10002
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 21 22 23 25 3306
CMD ["python", "/srv/banner_server.py"]
