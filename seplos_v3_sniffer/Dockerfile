ARG BUILD_ARCH=amd64
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base-python:3.12-alpine3.20

# paho-mqtt (EPL-2.0/EDL-1.0) is vendored under /app/vendor so the image builds
# with COPY only: no RUN steps, no BuildKit frontend pull, no network sandbox
# needed during the build. run.sh is executable in git, so plain COPY keeps it.
COPY vendor /app/vendor
COPY seplos_v3_sniffer.py /app/seplos_v3_sniffer.py
COPY run.sh /run.sh
ENV PYTHONPATH=/app/vendor

CMD [ "/run.sh" ]
