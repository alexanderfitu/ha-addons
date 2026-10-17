#!/usr/bin/env python3
"""
Seplos V3 BMS multipack sniffer  ->  Home Assistant via MQTT discovery.

Listens (receive-only) to the RS485 bus between a Seplos V3 master pack and
its slaves, carried to the network by a Waveshare RS485-to-Ethernet module in
transparent TCP-server mode.  Decodes the Modbus RTU *responses* that fly past
(PIA telemetry, PIB cells/temps, PIC alarms/status) and publishes one JSON
state document per pack plus a bank summary.

Nothing is ever transmitted onto the bus.

Frame layout (from the Seplos V3 protocol / DpunktS sniffer):
  <addr> 04 24 <36 bytes>  CRC16   telemetry   (registers 0x1000.., 18 regs)
  <addr> 04 34 <52 bytes>  CRC16   cells/temps (registers 0x1100.., 26 regs)
  <addr> 01 12 <18 bytes>  CRC16   coils/alarms (0x1200.., 144 coils)

Environment variables (or /etc/default/seplos-sniffer):
  SNIFF_HOST          Waveshare IP            (required)
  SNIFF_PORT          Waveshare TCP port      (default 8899)
  MQTT_HOST           MQTT broker             (default homeassistant.local)
  MQTT_PORT                                   (default 1883)
  MQTT_USER / MQTT_PASS
  MQTT_PREFIX         base topic              (default seplos)
  DISCOVERY_PREFIX    HA discovery prefix     (default homeassistant)
  PUBLISH_INTERVAL    seconds between publishes (default 5)
  STALE_AFTER         seconds before a pack is marked unavailable (default 60)
  LOG_LEVEL           DEBUG/INFO/WARNING      (default INFO)

Command line:
  --dump      print every valid frame as hex (bus verification)
  --no-mqtt   decode and print values only, never connect to MQTT
"""

import argparse
import json
import logging
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import paho.mqtt.client as mqtt
except ImportError:  # --no-mqtt still works without paho
    mqtt = None

log = logging.getLogger("seplos")

# ----------------------------------------------------------------------------
# Modbus CRC-16 (poly 0xA001, init 0xFFFF), little-endian on the wire
# ----------------------------------------------------------------------------
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc


def crc_ok(frame: bytes) -> bool:
    return crc16(frame[:-2]) == (frame[-1] << 8 | frame[-2])


# ----------------------------------------------------------------------------
# Frame recognition
# ----------------------------------------------------------------------------
FRAME_TYPES = {
    (0x04, 0x24): ("pia", 3 + 36 + 2),
    (0x04, 0x34): ("pib", 3 + 52 + 2),
    (0x01, 0x12): ("pic", 3 + 18 + 2),
}
MAX_ADDR = 0x10


def header_type(buf: bytes):
    if len(buf) < 3 or buf[0] > MAX_ADDR:
        return None
    return FRAME_TYPES.get((buf[1], buf[2]))


def u16(b, o):
    return b[o] << 8 | b[o + 1]


def i16(b, o):
    v = u16(b, o)
    return v - 0x10000 if v & 0x8000 else v


def kelvin(v):
    return round(v / 10 - 273.15, 1)


# ----------------------------------------------------------------------------
# Decoders
# ----------------------------------------------------------------------------
def decode_pia(p: bytes) -> dict:
    """36-byte telemetry payload."""
    d = {
        "voltage": u16(p, 0) / 100,
        "current": i16(p, 2) / 100,            # +ve = charging
        "remaining_capacity": u16(p, 4) / 100,  # Ah
        "total_capacity": u16(p, 6) / 100,      # Ah
        "total_discharge_capacity": u16(p, 8) / 10,  # Ah (0.1 Ah units)
        "soc": u16(p, 10) / 10,
        "soh": u16(p, 12) / 10,
        "cycles": u16(p, 14),
        "avg_cell_voltage": u16(p, 16) / 1000,
        "avg_cell_temp": kelvin(u16(p, 18)),
        "max_cell_voltage": u16(p, 20) / 1000,
        "min_cell_voltage": u16(p, 22) / 1000,
        "max_cell_temp": kelvin(u16(p, 24)),
        "min_cell_temp": kelvin(u16(p, 26)),
        "max_discharge_current": u16(p, 30),
        "max_charge_current": u16(p, 32),
    }
    d["delta_cell_voltage"] = round((u16(p, 20) - u16(p, 22)) / 1000, 3)
    d["power"] = round(d["voltage"] * d["current"], 1)
    d["remaining_energy"] = round(d["remaining_capacity"] * d["voltage"] / 1000, 2)  # kWh
    return d


def decode_pib(p: bytes) -> dict:
    """52-byte cells/temps payload."""
    d = {}
    for i in range(16):
        d[f"cell_{i + 1}_voltage"] = u16(p, i * 2) / 1000
    for i in range(4):
        d[f"cell_temp_{i + 1}"] = kelvin(u16(p, 32 + i * 2))
    d["env_temp"] = kelvin(u16(p, 48))
    d["mosfet_temp"] = kelvin(u16(p, 50))
    return d


def _cells(lo, hi=0):
    bits = lo | (hi << 8)
    return [i + 1 for i in range(16) if bits >> i & 1]


SYSTEM_STATUS = [(0x01, "discharge"), (0x02, "charge"), (0x04, "floating_charge"),
                 (0x08, "full_charge"), (0x10, "standby"), (0x20, "off")]
FET_STATUS = [(0x01, "discharge_fet"), (0x02, "charge_fet"),
              (0x04, "current_limit_fet"), (0x08, "heater")]

# (byte offset in payload, mask, name, is_protection)
EVENTS = [
    # TB02 voltage
    (9, 0x01, "cell_high_voltage_alarm", False), (9, 0x02, "cell_over_voltage_protection", True),
    (9, 0x04, "cell_low_voltage_alarm", False), (9, 0x08, "cell_under_voltage_protection", True),
    (9, 0x10, "pack_high_voltage_alarm", False), (9, 0x20, "pack_over_voltage_protection", True),
    (9, 0x40, "pack_low_voltage_alarm", False), (9, 0x80, "pack_under_voltage_protection", True),
    # TB03 temperature
    (10, 0x01, "charge_high_temp_alarm", False), (10, 0x02, "charge_over_temp_protection", True),
    (10, 0x04, "charge_low_temp_alarm", False), (10, 0x08, "charge_under_temp_protection", True),
    (10, 0x10, "discharge_high_temp_alarm", False), (10, 0x20, "discharge_over_temp_protection", True),
    (10, 0x40, "discharge_low_temp_alarm", False), (10, 0x80, "discharge_under_temp_protection", True),
    # TB04 environment / power
    (11, 0x01, "env_high_temp_alarm", False), (11, 0x02, "env_over_temp_protection", True),
    (11, 0x04, "env_low_temp_alarm", False), (11, 0x08, "env_under_temp_protection", True),
    (11, 0x10, "mosfet_high_temp_alarm", False), (11, 0x20, "mosfet_over_temp_protection", True),
    (11, 0x40, "cell_low_temp_heating", False),
    # TB05 current
    (12, 0x01, "charge_current_alarm", False), (12, 0x02, "charge_over_current_protection", True),
    (12, 0x04, "charge_2nd_over_current_protection", True), (12, 0x08, "discharge_current_alarm", False),
    (12, 0x10, "discharge_over_current_protection", True), (12, 0x20, "discharge_2nd_over_current_protection", True),
    (12, 0x40, "short_circuit_protection", True),
    # TB16 latch
    (13, 0x01, "short_circuit_latch", False), (13, 0x04, "charge_2nd_latch", False), (13, 0x08, "discharge_2nd_latch", False),
    # TB06 capacity
    (14, 0x04, "soc_alarm", False), (14, 0x08, "soc_protection", True), (14, 0x10, "cell_difference_alarm", False),
    # TB08 equalisation / modes
    (16, 0x01, "low_soc_alarm", False), (16, 0x02, "intermittent_charge", False),
    (16, 0x04, "external_switch_control", False), (16, 0x08, "static_standby_sleep", False),
    (16, 0x10, "history_data_recording", False), (16, 0x20, "under_soc_protection", True),
    (16, 0x40, "active_limited_current", False), (16, 0x80, "passive_limited_current", False),
    # TB15 hard faults (all protections)
    (17, 0x01, "ntc_fault", True), (17, 0x02, "afe_fault", True), (17, 0x04, "charge_mosfet_fault", True),
    (17, 0x08, "discharge_mosfet_fault", True), (17, 0x10, "cell_fault", True),
    (17, 0x20, "break_line_fault", True), (17, 0x40, "key_fault", True), (17, 0x80, "aerosol_alarm", True),
]
# Informational bits that are not really alarms
INFO_EVENTS = {"intermittent_charge", "external_switch_control", "static_standby_sleep",
               "history_data_recording", "active_limited_current", "passive_limited_current",
               "cell_low_temp_heating"}


def decode_pic(p: bytes) -> dict:
    """18-byte coil payload: alarms, status, protections."""
    d = {
        "cells_low_voltage": _cells(p[0], p[1]),
        "cells_high_voltage": _cells(p[2], p[3]),
        "cells_low_temp": _cells(p[4]),
        "cells_high_temp": _cells(p[5]),
        "cells_balancing": _cells(p[6], p[7]),
    }
    status = [n for m, n in SYSTEM_STATUS if p[8] & m]
    d["system_status"] = ",".join(status) or "unknown"
    d["fet_status"] = ",".join(n for m, n in FET_STATUS if p[15] & m) or "none"
    alarms, prots, infos = [], [], []
    for off, mask, name, is_prot in EVENTS:
        if p[off] & mask:
            (infos if name in INFO_EVENTS else prots if is_prot else alarms).append(name)
    d["active_alarms"] = ",".join(alarms) or "none"
    d["active_protections"] = ",".join(prots) or "none"
    d["info_flags"] = ",".join(infos) or "none"
    d["problem"] = bool(alarms or prots)
    d["charging"] = "charge" in status or "floating_charge" in status
    d["discharging"] = "discharge" in status
    d["balancing"] = bool(d["cells_balancing"])
    d["heating"] = bool(p[15] & 0x08)
    return d


# ----------------------------------------------------------------------------
# Stream parser
# ----------------------------------------------------------------------------
class Parser:
    def __init__(self, on_frame):
        self.buf = bytearray()
        self.on_frame = on_frame
        self.frames = 0
        self.crc_errors = 0
        self.requests = 0

    def feed(self, data: bytes):
        self.buf += data
        while len(self.buf) >= 3:
            ft = header_type(self.buf)
            if ft is None:
                del self.buf[0]
                continue
            kind, length = ft
            if len(self.buf) < length:
                return  # wait for more
            frame = bytes(self.buf[:length])
            if crc_ok(frame):
                self.frames += 1
                self.on_frame(frame[0], kind, frame[3:-2], frame)
                del self.buf[:length]
            elif crc_ok(bytes(self.buf[:8])):
                # the master's 8-byte request (e.g. "03 01 12 00 00 90 crc") shares
                # a header with a PIC response; skip it without counting an error
                self.requests += 1
                del self.buf[:8]
            else:
                self.crc_errors += 1
                del self.buf[0]
        if len(self.buf) > 4096:
            del self.buf[:-512]


# ----------------------------------------------------------------------------
# Home Assistant MQTT discovery
# ----------------------------------------------------------------------------
# key, name, unit, device_class, state_class, icon, enabled_by_default
PACK_SENSORS = [
    ("voltage", "Voltage", "V", "voltage", "measurement", None, True),
    ("current", "Current", "A", "current", "measurement", None, True),
    ("power", "Power", "W", "power", "measurement", None, True),
    ("soc", "State of charge", "%", "battery", "measurement", None, True),
    ("soh", "State of health", "%", None, "measurement", "mdi:heart-pulse", True),
    ("remaining_capacity", "Remaining capacity", "Ah", None, "measurement", "mdi:battery-medium", True),
    ("total_capacity", "Total capacity", "Ah", None, "measurement", "mdi:battery", False),
    ("remaining_energy", "Remaining energy", "kWh", "energy_storage", "measurement", None, True),
    ("total_discharge_capacity", "Lifetime discharge", "Ah", None, "total_increasing", "mdi:counter", False),
    ("cycles", "Cycles", None, None, "total_increasing", "mdi:recycle", True),
    ("avg_cell_voltage", "Average cell voltage", "V", "voltage", "measurement", None, False),
    ("max_cell_voltage", "Max cell voltage", "V", "voltage", "measurement", None, True),
    ("min_cell_voltage", "Min cell voltage", "V", "voltage", "measurement", None, True),
    ("delta_cell_voltage", "Cell delta", "V", "voltage", "measurement", "mdi:delta", True),
    ("avg_cell_temp", "Average cell temperature", "°C", "temperature", "measurement", None, True),
    ("max_cell_temp", "Max cell temperature", "°C", "temperature", "measurement", None, False),
    ("min_cell_temp", "Min cell temperature", "°C", "temperature", "measurement", None, False),
    ("env_temp", "Environment temperature", "°C", "temperature", "measurement", None, True),
    ("mosfet_temp", "MOSFET temperature", "°C", "temperature", "measurement", None, True),
    ("max_charge_current", "BMS charge limit", "A", "current", "measurement", None, True),
    ("max_discharge_current", "BMS discharge limit", "A", "current", "measurement", None, True),
    ("system_status", "System status", None, None, None, "mdi:state-machine", True),
    ("fet_status", "FET status", None, None, None, "mdi:electric-switch", False),
    ("active_alarms", "Active alarms", None, None, None, "mdi:alert", True),
    ("active_protections", "Active protections", None, None, None, "mdi:shield-alert", True),
    ("info_flags", "Info flags", None, None, None, "mdi:information", False),
    ("cells_balancing_str", "Balancing cells", None, None, None, "mdi:scale-balance", False),
] + [(f"cell_{i}_voltage", f"Cell {i} voltage", "V", "voltage", "measurement", None, False) for i in range(1, 17)] \
  + [(f"cell_temp_{i}", f"Cell temperature {i}", "°C", "temperature", "measurement", None, False) for i in range(1, 5)]

PACK_BINARY = [
    ("problem", "Problem", "problem"),
    ("charging", "Charging", "battery_charging"),
    ("discharging", "Discharging", None),
    ("balancing", "Balancing", None),
    ("heating", "Heater", "heat"),
]

BANK_SENSORS = [
    ("pack_count", "Packs online", None, None, "measurement", "mdi:battery-multiple", True),
    ("voltage", "Bus voltage", "V", "voltage", "measurement", None, True),
    ("current", "Total current", "A", "current", "measurement", None, True),
    ("power", "Total power", "W", "power", "measurement", None, True),
    ("soc", "Average SOC", "%", "battery", "measurement", None, True),
    ("min_soc", "Lowest pack SOC", "%", "battery", "measurement", None, True),
    ("max_soc", "Highest pack SOC", "%", "battery", "measurement", None, True),
    ("remaining_capacity", "Remaining capacity", "Ah", None, "measurement", "mdi:battery-medium", True),
    ("remaining_energy", "Remaining energy", "kWh", "energy_storage", "measurement", None, True),
    ("min_cell_voltage", "Lowest cell", "V", "voltage", "measurement", None, True),
    ("max_cell_voltage", "Highest cell", "V", "voltage", "measurement", None, True),
    ("max_cell_temp", "Hottest cell", "°C", "temperature", "measurement", None, True),
    ("min_cell_temp", "Coldest cell", "°C", "temperature", "measurement", None, True),
    ("max_charge_current", "Sum of charge limits", "A", "current", "measurement", None, True),
    ("max_discharge_current", "Sum of discharge limits", "A", "current", "measurement", None, True),
    ("frames", "Frames decoded", None, None, "total_increasing", "mdi:counter", False),
    ("crc_errors", "CRC errors", None, None, "total_increasing", "mdi:alert-circle", False),
]


class Publisher:
    def __init__(self, cfg):
        self.cfg = cfg
        self.prefix = cfg["MQTT_PREFIX"]
        self.disc = cfg["DISCOVERY_PREFIX"]
        self.avail = f"{self.prefix}/status"
        self.announced = set()
        self.names = cfg.get("PACK_NAMES", {})
        if hasattr(mqtt, "CallbackAPIVersion"):  # paho-mqtt 2.x
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id="seplos-v3-sniffer")
        else:
            self.client = mqtt.Client(client_id="seplos-v3-sniffer")
        if cfg.get("MQTT_USER"):
            self.client.username_pw_set(cfg["MQTT_USER"], cfg.get("MQTT_PASS") or None)
        self.client.will_set(self.avail, "offline", retain=True)
        self.client.on_connect = self._on_connect
        self.client.connect_async(cfg["MQTT_HOST"], int(cfg["MQTT_PORT"]), keepalive=30)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, rc):
        log.info("MQTT connected (rc=%s)", rc)
        client.publish(self.avail, "online", retain=True)
        self.announced.clear()  # re-announce discovery after reconnect

    def _device(self, uid, name, model):
        return {"identifiers": [uid], "name": name, "manufacturer": "Seplos / Fogstar",
                "model": model, "via_device": "seplos_v3_bank"}

    def announce_pack(self, addr):
        uid = f"seplos_pack_{addr}"
        if uid in self.announced:
            return
        dev = self._device(uid, self.names.get(addr, f"Fogstar pack {addr}"), "16.1 kWh ECO (Seplos V3)")
        dev["via_device"] = "seplos_v3_bank"
        state = f"{self.prefix}/pack_{addr}/state"
        pavail = f"{self.prefix}/pack_{addr}/availability"
        avail = [{"topic": self.avail}, {"topic": pavail}]
        for key, name, unit, dc, sc, icon, enabled in PACK_SENSORS:
            cfg = {"name": name, "unique_id": f"{uid}_{key}", "state_topic": state,
                   "value_template": "{{ value_json.%s }}" % key, "device": dev,
                   "availability": avail, "availability_mode": "all",
                   "enabled_by_default": enabled}
            if unit: cfg["unit_of_measurement"] = unit
            if dc: cfg["device_class"] = dc
            if sc: cfg["state_class"] = sc
            if icon: cfg["icon"] = icon
            self.client.publish(f"{self.disc}/sensor/{uid}/{key}/config", json.dumps(cfg), retain=True)
        for key, name, dc in PACK_BINARY:
            cfg = {"name": name, "unique_id": f"{uid}_{key}", "state_topic": state,
                   "value_template": "{{ 'ON' if value_json.%s else 'OFF' }}" % key,
                   "device": dev, "availability": avail, "availability_mode": "all"}
            if dc: cfg["device_class"] = dc
            self.client.publish(f"{self.disc}/binary_sensor/{uid}/{key}/config", json.dumps(cfg), retain=True)
        self.announced.add(uid)
        log.info("announced %s to Home Assistant", uid)

    def announce_bank(self):
        uid = "seplos_v3_bank"
        if uid in self.announced:
            return
        dev = {"identifiers": [uid], "name": "Fogstar battery bank", "manufacturer": "Seplos / Fogstar",
               "model": "V3 multipack sniffer"}
        state = f"{self.prefix}/bank/state"
        for key, name, unit, dc, sc, icon, enabled in BANK_SENSORS:
            cfg = {"name": name, "unique_id": f"{uid}_{key}", "state_topic": state,
                   "value_template": "{{ value_json.%s }}" % key, "device": dev,
                   "availability_topic": self.avail, "enabled_by_default": enabled}
            if unit: cfg["unit_of_measurement"] = unit
            if dc: cfg["device_class"] = dc
            if sc: cfg["state_class"] = sc
            if icon: cfg["icon"] = icon
            self.client.publish(f"{self.disc}/sensor/{uid}/{key}/config", json.dumps(cfg), retain=True)
        cfg = {"name": "Problem", "unique_id": f"{uid}_problem", "state_topic": state,
               "value_template": "{{ 'ON' if value_json.problem else 'OFF' }}",
               "device_class": "problem", "device": dev, "availability_topic": self.avail}
        self.client.publish(f"{self.disc}/binary_sensor/{uid}/problem/config", json.dumps(cfg), retain=True)
        self.announced.add(uid)

    def publish_pack(self, addr, data, online):
        self.announce_bank()
        self.announce_pack(addr)
        self.client.publish(f"{self.prefix}/pack_{addr}/availability", "online" if online else "offline", retain=True)
        if online:
            self.client.publish(f"{self.prefix}/pack_{addr}/state", json.dumps(data))

    def publish_bank(self, data):
        self.announce_bank()
        self.client.publish(f"{self.prefix}/bank/state", json.dumps(data))


# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------
class Sniffer:
    def __init__(self, cfg, args):
        self.cfg = cfg
        self.args = args
        self.packs = {}       # addr -> merged dict
        self.seen = {}        # addr -> last frame time
        self.lock = threading.Lock()
        self.parser = Parser(self.on_frame)
        self.link = "connecting"
        self.started = time.time()
        self.pub = None
        if not args.no_mqtt:
            if mqtt is None:
                sys.exit("paho-mqtt is not installed (pip install paho-mqtt) or use --no-mqtt")
            self.pub = Publisher(cfg)

    def on_frame(self, addr, kind, payload, frame):
        if self.args.dump:
            print(f"{time.strftime('%H:%M:%S')} pack {addr:2d} {kind.upper()} {frame.hex(' ')}")
        try:
            data = {"pia": decode_pia, "pib": decode_pib, "pic": decode_pic}[kind](payload)
        except Exception as e:  # malformed but CRC-valid frame; keep going
            log.warning("decode error pack %s %s: %s", addr, kind, e)
            return
        with self.lock:
            self.packs.setdefault(addr, {}).update(data)
            self.seen[addr] = time.time()

    def reader(self):
        host, port = self.cfg["SNIFF_HOST"], int(self.cfg["SNIFF_PORT"])
        delay = 2
        while True:
            try:
                log.info("connecting to %s:%s", host, port)
                with socket.create_connection((host, port), timeout=10) as s:
                    s.settimeout(30)
                    log.info("connected; listening")
                    self.link = "connected"
                    delay = 2
                    while True:
                        chunk = s.recv(1024)
                        if not chunk:
                            raise ConnectionError("socket closed by Waveshare")
                        self.parser.feed(chunk)
            except (OSError, ConnectionError) as e:
                self.link = f"down: {e}"
                log.warning("link down: %s; retry in %ss", e, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def snapshot(self):
        now = time.time()
        stale = float(self.cfg["STALE_AFTER"])
        with self.lock:
            packs = {a: dict(d) for a, d in self.packs.items()}
            seen = dict(self.seen)
        online = {a: d for a, d in packs.items() if now - seen[a] < stale and "voltage" in d}
        for d in packs.values():
            d["cells_balancing_str"] = ",".join(map(str, d.get("cells_balancing", []))) or "none"
        bank = {"pack_count": len(online), "frames": self.parser.frames, "crc_errors": self.parser.crc_errors,
                "link": self.link, "problem": any(d.get("problem") for d in online.values())}
        if online:
            vals = list(online.values())
            bank.update({
                "voltage": round(sum(d["voltage"] for d in vals) / len(vals), 2),
                "current": round(sum(d["current"] for d in vals), 2),
                "power": round(sum(d["power"] for d in vals), 1),
                "soc": round(sum(d["soc"] for d in vals) / len(vals), 1),
                "min_soc": min(d["soc"] for d in vals),
                "max_soc": max(d["soc"] for d in vals),
                "remaining_capacity": round(sum(d["remaining_capacity"] for d in vals), 2),
                "remaining_energy": round(sum(d["remaining_energy"] for d in vals), 2),
                "min_cell_voltage": min(d["min_cell_voltage"] for d in vals),
                "max_cell_voltage": max(d["max_cell_voltage"] for d in vals),
                "max_cell_temp": max(d["max_cell_temp"] for d in vals),
                "min_cell_temp": min(d["min_cell_temp"] for d in vals),
                "max_charge_current": sum(d["max_charge_current"] for d in vals),
                "max_discharge_current": sum(d["max_discharge_current"] for d in vals),
            })
        return packs, online, bank

    def run(self):
        threading.Thread(target=self.reader, daemon=True).start()
        if self.cfg.get("WEB_PORT"):
            threading.Thread(target=self.web, daemon=True).start()
        interval = float(self.cfg["PUBLISH_INTERVAL"])
        while True:
            time.sleep(interval)
            packs, online, bank = self.snapshot()
            if self.args.no_mqtt:
                for a in sorted(packs):
                    d = packs[a]
                    flag = "" if a in online else " (STALE)"
                    print(f"pack {a}{flag}: {d.get('voltage')} V {d.get('current')} A soc {d.get('soc')}% "
                          f"cells {d.get('min_cell_voltage')}-{d.get('max_cell_voltage')} "
                          f"status {d.get('system_status')} alarms {d.get('active_alarms')} prot {d.get('active_protections')}")
                print(f"bank: {bank}")
                continue
            for a, d in packs.items():
                self.pub.publish_pack(a, d, a in online)
            self.pub.publish_bank(bank)

    # ------------------------------------------------------------------ web UI
    def web(self):
        sniffer = self
        names = self.cfg.get("PACK_NAMES", {})

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, body, ctype):
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_GET(self):
                packs, online, bank = sniffer.snapshot()
                if self.path.rstrip("/").endswith("/api/state") or self.path == "/api/state":
                    self._send(json.dumps({"bank": bank, "packs": {str(a): d for a, d in packs.items()},
                                           "online": sorted(online)}), "application/json")
                    return
                self._send(render(packs, online, bank, names, sniffer), "text/html; charset=utf-8")

        srv = ThreadingHTTPServer(("0.0.0.0", int(self.cfg["WEB_PORT"])), H)
        log.info("web UI on port %s", self.cfg["WEB_PORT"])
        srv.serve_forever()


def render(packs, online, bank, names, sniffer):
    def row(label, key, fmt="{}", unit=""):
        cells = "".join(f"<td>{fmt.format(packs[a].get(key)) if packs[a].get(key) is not None else '–'}{unit}</td>"
                        for a in sorted(packs))
        return f"<tr><th>{label}</th>{cells}</tr>"
    heads = "".join(
        f"<th class='{'ok' if a in online else 'stale'}'>{names.get(a, f'Pack {a}')}<br><small>bus {a}"
        f"{'' if a in online else ' · stale'}</small></th>" for a in sorted(packs))
    rows = "".join([
        row("Voltage", "voltage", "{:.2f}", " V"), row("Current", "current", "{:+.2f}", " A"),
        row("Power", "power", "{:+.0f}", " W"), row("SOC", "soc", "{:.1f}", " %"), row("SOH", "soh", "{:.1f}", " %"),
        row("Remaining", "remaining_capacity", "{:.1f}", " Ah"), row("Remaining", "remaining_energy", "{:.2f}", " kWh"),
        row("Cycles", "cycles"), row("Cell min", "min_cell_voltage", "{:.3f}", " V"),
        row("Cell max", "max_cell_voltage", "{:.3f}", " V"), row("Cell delta", "delta_cell_voltage", "{:.3f}", " V"),
        row("Cell temp", "avg_cell_temp", "{:.1f}", " °C"), row("MOSFET", "mosfet_temp", "{:.1f}", " °C"),
        row("Env", "env_temp", "{:.1f}", " °C"), row("Charge limit", "max_charge_current", "{}", " A"),
        row("Discharge limit", "max_discharge_current", "{}", " A"), row("Status", "system_status"),
        row("FETs", "fet_status"), row("Balancing", "cells_balancing_str"), row("Alarms", "active_alarms"),
        row("Protections", "active_protections"),
    ])
    cellrows = ""
    for i in range(1, 17):
        cellrows += f"<tr><th>Cell {i}</th>" + "".join(
            f"<td>{packs[a].get(f'cell_{i}_voltage', '–')}</td>" for a in sorted(packs)) + "</tr>"
    up = int(time.time() - sniffer.started)
    link = bank.get("link", "")
    b = bank
    summary = "" if not online else (
        f"<div class='cards'>"
        f"<div><b>{b['soc']:.1f} %</b><span>avg SOC ({b['min_soc']}–{b['max_soc']})</span></div>"
        f"<div><b>{b['remaining_energy']:.1f} kWh</b><span>remaining</span></div>"
        f"<div><b>{b['current']:+.1f} A</b><span>{b['power']:+.0f} W total</span></div>"
        f"<div><b>{b['min_cell_voltage']:.3f}–{b['max_cell_voltage']:.3f} V</b><span>cell range</span></div>"
        f"<div><b>{b['max_cell_temp']:.1f} °C</b><span>hottest cell</span></div>"
        f"<div><b>{b['max_charge_current']} A</b><span>sum of charge limits</span></div>"
        f"</div>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Battery bank</title>
<style>
body{{font-family:system-ui,sans-serif;margin:16px;background:#111;color:#eee}}
h1{{font-size:1.2rem;margin:0 0 8px}} .meta{{color:#9a9;font-size:.85rem;margin-bottom:12px}}
.meta.bad{{color:#f66}}
.cards{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}}
.cards div{{background:#1e1e1e;border-radius:8px;padding:10px 14px;min-width:120px}}
.cards b{{display:block;font-size:1.25rem}} .cards span{{font-size:.75rem;color:#aaa}}
table{{border-collapse:collapse;width:100%;max-width:900px;margin-bottom:16px}}
th,td{{padding:5px 8px;border-bottom:1px solid #2a2a2a;text-align:right;font-size:.9rem}}
th:first-child{{text-align:left;color:#aaa;font-weight:normal}} thead th{{text-align:right}}
th.ok{{color:#8e8}} th.stale{{color:#f88}} details{{margin-top:8px}}
</style></head><body>
<h1>Seplos V3 bank · {b['pack_count']} pack(s) online</h1>
<div class="meta {'bad' if link != 'connected' else ''}">Waveshare link: {link} · frames {b['frames']} · CRC errors {b['crc_errors']} · up {up // 3600}h {up % 3600 // 60}m</div>
{summary}
<table><thead><tr><th></th>{heads}</tr></thead><tbody>{rows}</tbody></table>
<details><summary>Cell voltages</summary><table><tbody>{cellrows}</tbody></table></details>
</body></html>"""


def load_config():
    defaults = {"SNIFF_PORT": "8899", "MQTT_HOST": "homeassistant.local", "MQTT_PORT": "1883",
                "MQTT_PREFIX": "seplos", "DISCOVERY_PREFIX": "homeassistant",
                "PUBLISH_INTERVAL": "5", "STALE_AFTER": "60", "LOG_LEVEL": "INFO"}
    cfg = {k: os.environ.get(k, v) for k, v in defaults.items()}
    for k in ("SNIFF_HOST", "MQTT_USER", "MQTT_PASS", "WEB_PORT"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    cfg["PACK_NAMES"] = {}
    # Home Assistant add-on: /data/options.json carries the web-form settings
    opts_file = os.environ.get("OPTIONS_FILE", "/data/options.json")
    if os.path.exists(opts_file):
        with open(opts_file) as f:
            o = json.load(f)
        m = {"waveshare_host": "SNIFF_HOST", "waveshare_port": "SNIFF_PORT", "publish_interval": "PUBLISH_INTERVAL",
             "stale_after": "STALE_AFTER", "mqtt_prefix": "MQTT_PREFIX", "discovery_prefix": "DISCOVERY_PREFIX",
             "log_level": "LOG_LEVEL", "mqtt_host": "MQTT_HOST", "mqtt_port": "MQTT_PORT",
             "mqtt_user": "MQTT_USER", "mqtt_password": "MQTT_PASS"}
        for ok, ck in m.items():
            v = o.get(ok)
            if v not in (None, ""):
                cfg[ck] = str(v).upper() if ck == "LOG_LEVEL" else str(v)
        for item in o.get("pack_names") or []:
            try:
                cfg["PACK_NAMES"][int(item["address"])] = str(item["name"])
            except (KeyError, ValueError, TypeError):
                pass
    return cfg


def main():
    ap = argparse.ArgumentParser(description="Seplos V3 RS485 sniffer -> MQTT")
    ap.add_argument("--host", help="Waveshare IP (overrides SNIFF_HOST)")
    ap.add_argument("--port", type=int, help="Waveshare TCP port (overrides SNIFF_PORT)")
    ap.add_argument("--dump", action="store_true", help="print every valid frame as hex")
    ap.add_argument("--no-mqtt", action="store_true", help="decode to stdout only")
    args = ap.parse_args()
    cfg = load_config()
    if args.host: cfg["SNIFF_HOST"] = args.host
    if args.port: cfg["SNIFF_PORT"] = str(args.port)
    if not cfg.get("SNIFF_HOST"):
        sys.exit("SNIFF_HOST (or --host) is required")
    logging.basicConfig(level=cfg["LOG_LEVEL"], format="%(asctime)s %(levelname)s %(message)s")
    try:
        Sniffer(cfg, args).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
