# Seplos V3 Battery Sniffer

Passive listener for the RS485 bus between a Seplos V3 master pack and its
slaves (Fogstar 16.1 kWh ECO and other Seplos V3-based packs). The master polls
each pack about every 200 ms; this add-on decodes those responses from a
Waveshare RS485-to-Ethernet bridge and publishes every pack to MQTT with Home
Assistant discovery. It never transmits on the bus, so the chain and the
inverter's CAN link are untouched.

## Hardware

Any pack's **RS485/CAN** socket (use a slave so the inverter lead stays put):

| RJ45 pin | Signal | Waveshare |
|---|---|---|
| 2 or 7 | RS485-A | A (T/R+, D+) |
| 1 or 8 | RS485-B | B (T/R−, D−) |
| 3 or 6 | GND | GND |

Pins 4/5 are CAN: leave them. No termination resistor. Garbage = swap A and B.

Waveshare web UI: **TCP Server**, local port **8899**, transfer protocol
**None** (not Modbus TCP), **19200 8N1**, static IP.

## Options

| Option | Meaning |
|---|---|
| `waveshare_host` | IP of the Waveshare bridge (required) |
| `waveshare_port` | Its TCP server port (8899) |
| `publish_interval` | Seconds between MQTT publishes |
| `stale_after` | Seconds without frames before a pack is marked unavailable |
| `mqtt_prefix` | Base topic (`seplos`) |
| `discovery_prefix` | HA discovery prefix (`homeassistant`) |
| `pack_names` | Friendly name per bus address, e.g. address 2 → "Garage pack A". The device in HA takes this name |
| `log_level` | debug / info / warning / error |
| `mqtt_host`, `mqtt_port`, `mqtt_user`, `mqtt_password` | Only needed if you are not using the Mosquitto add-on; otherwise the broker details come from the Supervisor automatically |

## What you get

- One device per pack: voltage, current (+ = charging), power, SOC, SOH,
  remaining Ah/kWh, cycles, min/max/avg/delta cell voltage, temperatures, BMS
  charge/discharge limits, status, alarms, protections, FET status, balancing
  cells, binary sensors for problem / charging / discharging / balancing /
  heater. Per-cell voltages and temps exist but are disabled by default.
- A "battery bank" device with pack count, bus voltage, total current/power,
  average/min/max SOC, total remaining Ah/kWh, cell extremes, summed limits and
  decoder counters.
- A sidebar panel ("Battery bank") showing everything live, plus
  `/api/state` JSON on the same ingress path.

Topics: `<prefix>/pack_<addr>/state`, `<prefix>/pack_<addr>/availability`,
`<prefix>/bank/state`, `<prefix>/status` (LWT).

## Troubleshooting

- **Link: down / connection refused** – the Waveshare is not in TCP Server mode
  on that port.
- **Link connected, no packs** – A/B swapped, wrong baud, or Modbus-TCP
  conversion is on in the Waveshare.
- **CRC errors climbing** – noisy line or a second device transmitting on the
  bus (e.g. BMS Studio).
- Bus addresses are the chain order (master = 1), not the labels on the
  cabinets; use `pack_names` to map them.
