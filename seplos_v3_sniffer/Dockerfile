# syntax=docker/dockerfile:1
ARG BUILD_ARCH=amd64
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base-python:3.12-alpine3.20

# paho-mqtt (EPL-2.0/EDL-1.0) is vendored under /app/vendor so the image builds
# with COPY only: no RUN steps, so no network sandbox is needed during the build.
COPY vendor /app/vendor
COPY seplos_v3_sniffer.py /app/seplos_v3_sniffer.py
COPY --chmod=755 run.sh /run.sh
ENV PYTHONPATH=/app/vendor

CMD [ "/run.sh" ]
