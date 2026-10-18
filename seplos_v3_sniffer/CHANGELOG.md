## 1.0.0
- Initial release: PIA/PIB/PIC decoding, MQTT discovery per pack + bank, ingress status page, pack naming.

## 1.0.1
- Vendor paho-mqtt and build with COPY only (no network needed during the Docker build).
- Drop deprecated build.yaml; base image set in the Dockerfile.

## 1.0.2
- Remove the `# syntax=docker/dockerfile:1` directive and `COPY --chmod` so the build needs no BuildKit frontend image from Docker Hub (1.0.1 build failed with empty output on a host with flaky container networking). run.sh is executable in git instead.

## 1.0.3
- Fix false `low_soc_alarm` / `under_soc_protection` on a pack that is balancing. PIC byte 16 bits 0 and 5 set together with the per-cell balancing bits at 100 % SOC (verified on a live Fogstar ECO frame), so they are now reported as info flags (`equalisation_active`, `equalisation_flag_bit5`) and no longer raise Problem.
