## 1.0.0
- Initial release: PIA/PIB/PIC decoding, MQTT discovery per pack + bank, ingress status page, pack naming.

## 1.0.1
- Vendor paho-mqtt and build with COPY only (no network needed during the Docker build).
- Drop deprecated build.yaml; base image set in the Dockerfile.

## 1.0.2
- Remove the `# syntax=docker/dockerfile:1` directive and `COPY --chmod` so the build needs no BuildKit frontend image from Docker Hub (1.0.1 build failed with empty output on a host with flaky container networking). run.sh is executable in git instead.
