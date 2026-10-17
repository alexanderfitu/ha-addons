## 1.0.0
- Initial release: PIA/PIB/PIC decoding, MQTT discovery per pack + bank, ingress status page, pack naming.

## 1.0.1
- Vendor paho-mqtt and build with COPY only (no network needed during the Docker build).
- Drop deprecated build.yaml; base image set in the Dockerfile.
