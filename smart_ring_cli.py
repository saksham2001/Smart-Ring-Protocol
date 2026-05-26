#!/usr/bin/env python3
"""
Interactive SMART_RING BLE tester.

Install dependency:
    python3 -m pip install bleak

Run:
    python3 smart_ring_cli.py

On macOS, the device address shown by Bleak is usually a CoreBluetooth UUID,
not the real BLE MAC address seen in Wireshark.
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
except ImportError:
    print("Missing dependency: bleak")
    print("Install it with: python3 -m pip install bleak")
    sys.exit(1)


DEVICE_NAME = "SMART_RING"
RING_MANUFACTURER_PREFIX = "41422ec75b6a"

WRITE_CHAR_UUID = "000033f3-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID = "000033f4-0000-1000-8000-00805f9b34fb"
BATTERY_CHAR_UUID = "00002a19-0000-1000-8000-00805f9b34fb"
HID_SERVICE_UUID = "00001812-0000-1000-8000-00805f9b34fb"
HID_REPORT_UUID = "00002a4d-0000-1000-8000-00805f9b34fb"
HID_BOOT_MOUSE_INPUT_UUID = "00002a33-0000-1000-8000-00805f9b34fb"
HID_REPORT_MAP_UUID = "00002a4b-0000-1000-8000-00805f9b34fb"

COMMANDS = {
    "status": "0c00000000000000000000000000000000000000",
    "locale_en_us": "21656e2d55530000000000000000000000000000",
    "spo2_start": "2301000000000000000000000000000000000000",
    "spo2_stop": "2300000000000000000000000000000000000000",
    "hr_start": "14b4000000000000000000000000000000000000",
    "hr_stop": "1500000000000000000000000000000000000000",
    "selfie_start": "0701000000000000000000000000000000000000",
    "selfie_stop": "0700000000000000000000000000000000000000",
    "find_candidate_04": "040a000000000000000000000000000000000000",
    "activity_query": "0299b85a00000000000000000000000000000000",
    "history_summary_query": "1000000000000000000000000000000000000000",
    "sleep_history_query": "1000000000000000000000000000000000000000",
    "history_measurement_query": "1600000000000000000000000000000000000000",
    "goal_10000_steps": "1a10270000000000000000000000000000000000",
    "mode_candidate_52_01": "5200000000010000000000000000000000000000",
    "mode_candidate_52_02": "5200000000020000000000000000000000000000",
    "mode_candidate_52_reset": "5200000000ffffffff0000000000000000000000",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def hex_to_bytes(value: str) -> bytes:
    clean = value.replace(" ", "").replace(":", "").strip()
    if len(clean) % 2:
        raise ValueError("hex string must have an even number of characters")
    return bytes.fromhex(clean)


def u32le(data: bytes, offset: int) -> int:
    if len(data) < offset + 4:
        return 0
    return int.from_bytes(data[offset : offset + 4], "little")


def timestamp_text(value: int) -> str:
    if not 1_500_000_000 <= value <= 2_000_000_000:
        return str(value)
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def build_time_sync_payload() -> bytes:
    now = datetime.now().astimezone()
    timestamp = int(now.timestamp())
    offset = now.utcoffset()
    offset_hours = int(offset.total_seconds() // 3600) if offset else 0
    payload = bytearray(20)
    payload[0] = 0x01
    payload[1:5] = timestamp.to_bytes(4, "little")
    payload[5] = offset_hours & 0xFF
    return bytes(payload)


def sleep_stage_name(value: int) -> str:
    if value == 0x28:
        return "light"
    if value == 0x63:
        return "deep"
    if value == 0x00:
        return "empty"
    return f"unknown_0x{value:02x}"


def parse_notification(data: bytes) -> dict:
    if not data:
        return {}

    cmd = data[0]
    parsed = {"command_id": f"0x{cmd:02x}"}

    if cmd == 0x01 and len(data) >= 6:
        timestamp = u32le(data, 1)
        tz = int.from_bytes(data[5:6], "little", signed=True)
        parsed.update(
            kind="time_sync_ack",
            timestamp=timestamp,
            timestamp_utc=timestamp_text(timestamp),
            timezone_offset_hours=tz,
        )
    elif cmd == 0x03 and len(data) >= 17:
        timestamp = u32le(data, 1)
        steps = u32le(data, 5)
        distance_units = u32le(data, 9)
        calories = u32le(data, 13)
        parsed.update(
            kind="activity",
            timestamp=timestamp,
            timestamp_utc=timestamp_text(timestamp),
            steps=steps,
            distance_units=distance_units,
            distance_km_guess=round(distance_units / 1000, 3),
            calories=calories,
        )
    elif cmd == 0x13 and len(data) >= 17:
        timestamp = u32le(data, 1)
        parsed.update(
            kind="activity_summary",
            timestamp=timestamp,
            timestamp_utc=timestamp_text(timestamp),
            field_a=u32le(data, 5),
            field_b=u32le(data, 9),
            steps=u32le(data, 13),
        )
    elif cmd == 0x0B and len(data) >= 2:
        parsed.update(kind="percent_status", percent=data[1])
    elif cmd == 0x10 and len(data) >= 15:
        timestamp = u32le(data, 1)
        parsed.update(
            kind="history_summary",
            timestamp=timestamp,
            timestamp_utc=timestamp_text(timestamp),
            field_a=u32le(data, 5),
            field_b=u32le(data, 9),
            field_c=u32le(data, 13),
        )
    elif cmd == 0x11 and len(data) >= 6:
        timestamp = u32le(data, 1)
        samples = list(data[5:])
        stage_counts = {}
        for sample in samples:
            stage = sleep_stage_name(sample)
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
        parsed.update(
            kind="sleep_timeline",
            timestamp=timestamp,
            timestamp_utc=timestamp_text(timestamp),
            samples=samples,
            stages=[sleep_stage_name(sample) for sample in samples],
            stage_counts=stage_counts,
            minutes=len(samples),
        )
    elif cmd == 0x16 and len(data) >= 7:
        subtype = data[1]
        parsed.update(kind="history_measurement_stream", subtype=f"0x{subtype:02x}")
        if subtype == 0xAA and len(data) >= 8:
            timestamp = u32le(data, 3)
            parsed.update(
                index=data[2],
                timestamp=timestamp,
                timestamp_utc=timestamp_text(timestamp),
                sample_type=data[7],
            )
        elif subtype == 0xA0 and len(data) >= 8:
            timestamp = u32le(data, 2)
            samples = list(data[8:])
            parsed.update(
                timestamp=timestamp,
                timestamp_utc=timestamp_text(timestamp),
                samples=samples,
                samples_hex=data[8:].hex(),
            )
    elif cmd == 0x1A and len(data) >= 5:
        parsed.update(kind="goal_or_config", value=u32le(data, 1))
    elif cmd == 0x20:
        parsed.update(kind="device_time_or_config")
    elif cmd == 0x48:
        parsed.update(kind="app_identifier", ascii=data[1:].rstrip(b"\x00").decode("ascii", "replace"))
    elif cmd == 0x02:
        parsed.update(kind="activity_query_ack")

    return parsed


class JsonlLogger:
    def __init__(self, path: Path):
        self.path = path
        self.file = path.open("a", encoding="utf-8")

    def write(self, event: str, **fields) -> None:
        row = {"ts": now_iso(), "event": event, **fields}
        self.file.write(json.dumps(row, sort_keys=True) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def setup_logging(log_dir: Path) -> tuple[logging.Logger, JsonlLogger]:
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    text_path = log_dir / f"smart-ring-{stamp}.log"
    jsonl_path = log_dir / f"smart-ring-{stamp}.jsonl"

    logger = logging.getLogger("smart-ring")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setLevel(logging.INFO)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    text = logging.FileHandler(text_path, encoding="utf-8")
    text.setLevel(logging.DEBUG)
    text.setFormatter(formatter)
    logger.addHandler(text)

    jsonl = JsonlLogger(jsonl_path)

    logger.info("Text log: %s", text_path)
    logger.info("JSONL log: %s", jsonl_path)
    jsonl.write("log_start", text_log=str(text_path), jsonl_log=str(jsonl_path))
    return logger, jsonl


def decode_notification(data: bytes) -> str:
    if not data:
        return "empty notification"

    cmd = data[0]
    parsed = parse_notification(data)

    if cmd == 0x01 and parsed:
        return (
            "time sync acknowledgement, "
            f"timestamp_utc={parsed.get('timestamp_utc')}, "
            f"tz={parsed.get('timezone_offset_hours')}"
        )

    if cmd == 0x03 and parsed:
        return (
            "activity packet, "
            f"steps={parsed.get('steps')}, "
            f"distance_units={parsed.get('distance_units')}, "
            f"distance_km_guess={parsed.get('distance_km_guess')}, "
            f"calories={parsed.get('calories')}, "
            f"timestamp_utc={parsed.get('timestamp_utc')}"
        )

    if cmd == 0x13 and parsed:
        return (
            "activity summary packet, "
            f"steps={parsed.get('steps')}, "
            f"field_a={parsed.get('field_a')}, "
            f"field_b={parsed.get('field_b')}, "
            f"timestamp_utc={parsed.get('timestamp_utc')}"
        )

    if cmd == 0x0C:
        parts = ["status response"]
        if len(data) >= 9:
            addr = ":".join(f"{b:02x}" for b in data[3:9])
            parts.append(f"embedded_addr={addr}")
        return ", ".join(parts)

    if cmd == 0x14:
        parts = ["heart-rate packet"]
        if len(data) >= 6:
            parts.append(f"possible_bpm={data[5]}")
        return ", ".join(parts)

    if cmd == 0x23:
        if len(data) > 1 and data[1] == 0x01:
            return "SpO2 start acknowledged"
        if len(data) > 1 and data[1] == 0x00:
            return "SpO2 stop acknowledged"
        return "SpO2 command/status"

    if cmd == 0x24:
        if data == bytes.fromhex("2400000000000000000000000000000000000000"):
            return "SpO2 progress/status"
        parts = ["SpO2 result/status"]
        if 0x50 <= data[4] <= 0x64:
            parts.append(f"possible_spo2_byte4={data[4]}")
        if 0x50 <= data[5] <= 0x64:
            parts.append(f"possible_spo2_byte5={data[5]}")
        return ", ".join(parts)

    if cmd == 0x27:
        return "measurement complete/status, likely HR-related"

    if cmd == 0x15:
        return "HR stop/cleanup acknowledgement"

    if cmd == 0x07:
        if len(data) > 1 and data[1] == 0x01:
            return "selfie mode enabled"
        if len(data) > 1 and data[1] == 0x00:
            return "selfie mode disabled"
        return "selfie mode command/status"

    if cmd == 0x06:
        if len(data) > 1 and data[1] == 0x02:
            return "selfie clench/shutter event"
        return "possible gesture/event"

    if cmd == 0x04:
        return "possible find-ring/light command acknowledgement"

    if cmd == 0x52:
        return "possible mode/light command acknowledgement"

    if cmd == 0x16:
        if parsed.get("kind") == "history_measurement_stream":
            parts = [f"history measurement stream subtype={parsed.get('subtype')}"]
            if "timestamp_utc" in parsed:
                parts.append(f"timestamp_utc={parsed['timestamp_utc']}")
            if "samples" in parsed:
                nonzero = [x for x in parsed["samples"] if x]
                if nonzero:
                    parts.append(f"samples={nonzero}")
            return ", ".join(parts)
        return "raw measurement stream/status packet"

    if cmd == 0x01:
        return "time sync command/status"

    if cmd == 0x02:
        return "activity query acknowledgement"

    if cmd == 0x03:
        return "activity packet"

    if cmd == 0x0B:
        return f"percent-like status value={data[1] if len(data) > 1 else 'unknown'}"

    if cmd == 0x10:
        if parsed.get("kind") == "history_summary":
            return (
                "history summary packet, "
                f"timestamp_utc={parsed.get('timestamp_utc')}, "
                f"field_a={parsed.get('field_a')}, "
                f"field_b={parsed.get('field_b')}, "
                f"field_c={parsed.get('field_c')}"
            )
        return "history summary packet"

    if cmd == 0x11:
        if parsed.get("kind") == "sleep_timeline":
            return (
                "sleep timeline packet, "
                f"timestamp_utc={parsed.get('timestamp_utc')}, "
                f"minutes={parsed.get('minutes')}, "
                f"stage_counts={parsed.get('stage_counts')}"
            )
        return "sleep timeline packet"

    if cmd == 0x1A:
        if parsed.get("kind") == "goal_or_config":
            return f"goal/config acknowledgement, value={parsed.get('value')}"
        return "goal/config acknowledgement"

    if cmd == 0x20:
        return "device time/config response"

    if cmd == 0x48:
        return f"app identifier acknowledgement, ascii={parsed.get('ascii')}"

    if cmd == 0x21:
        return "locale/language acknowledgement"

    return f"unknown command_id=0x{cmd:02x}"


class SmartRingCli:
    def __init__(self, logger: logging.Logger, jsonl: JsonlLogger):
        self.logger = logger
        self.jsonl = jsonl
        self.client: Optional[BleakClient] = None
        self.device = None
        self.notify_started = False
        self.hid_notify_started: set[str] = set()
        self.write_char = WRITE_CHAR_UUID
        self.notify_char = NOTIFY_CHAR_UUID

    def on_disconnect(self, client) -> None:
        self.notify_started = False
        self.hid_notify_started.clear()
        self.logger.info("Device disconnected.")
        self.jsonl.write("device_disconnected")

    @staticmethod
    def is_target_ring(row: dict) -> bool:
        if row["name"] == DEVICE_NAME:
            return True
        manufacturer_data = row.get("manufacturer_data", {})
        return any(
            value.lower().startswith(RING_MANUFACTURER_PREFIX)
            for value in manufacturer_data.values()
        )

    async def scan(self, timeout: float = 10.0):
        self.logger.info("Scanning for %.1fs...", timeout)
        self.jsonl.write("scan_start", timeout=timeout)
        try:
            devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
        except TypeError:
            plain_devices = await BleakScanner.discover(timeout=timeout)
            devices = {device.address: (device, None) for device in plain_devices}

        rows = []
        for index, (address, pair) in enumerate(devices.items(), start=1):
            device, adv = pair
            row = {
                "index": index,
                "name": device.name,
                "address": address,
                "rssi": getattr(adv, "rssi", None),
                "service_uuids": list(getattr(adv, "service_uuids", []) or []),
                "manufacturer_data": {
                    str(k): bytes(v).hex()
                    for k, v in (getattr(adv, "manufacturer_data", {}) or {}).items()
                },
            }
            rows.append((device, row))
            self.logger.info(
                "[%02d] name=%r address=%s rssi=%s services=%s mfg=%s",
                index,
                row["name"],
                row["address"],
                row["rssi"],
                row["service_uuids"],
                row["manufacturer_data"],
            )
            self.jsonl.write("scan_device", **row)

        matches = [(device, row) for device, row in rows if self.is_target_ring(row)]
        if matches:
            self.device = matches[0][0]
            self.logger.info(
                "Selected first target ring device: name=%r address=%s",
                matches[0][1]["name"],
                matches[0][1]["address"],
            )
            self.jsonl.write("scan_selected", **matches[0][1])
        else:
            self.logger.warning("No device named %s found.", DEVICE_NAME)
        self.jsonl.write("scan_done", count=len(rows), matches=len(matches))
        return rows

    async def connect(self, target: Optional[str] = None):
        if self.client and self.client.is_connected:
            self.logger.info("Already connected.")
            return

        if not target:
            if not self.device:
                await self.scan()
            if not self.device:
                raise RuntimeError("No selected device. Use scan or connect <address>.")
            target = self.device.address

        self.logger.info("Connecting to %s ...", target)
        self.jsonl.write("connect_start", target=target)
        self.notify_started = False
        self.client = BleakClient(target, disconnected_callback=self.on_disconnect)
        await self.client.connect()
        self.logger.info("Connected: %s", self.client.is_connected)
        self.jsonl.write("connect_done", target=target, connected=self.client.is_connected)

    async def disconnect(self):
        if not self.client:
            self.logger.info("No client exists.")
            return
        self.logger.info("Disconnecting...")
        self.jsonl.write("disconnect_start")
        if self.notify_started:
            await self.stop_notify()
        if self.hid_notify_started:
            await self.stop_hid_notify()
        if self.client.is_connected:
            await self.client.disconnect()
        self.notify_started = False
        self.hid_notify_started.clear()
        self.logger.info("Disconnected.")
        self.jsonl.write("disconnect_done")

    async def ensure_connected(self):
        if not self.client or not self.client.is_connected:
            await self.connect()

    async def services(self):
        await self.ensure_connected()
        assert self.client
        self.logger.info("Reading services/characteristics...")
        self.jsonl.write("services_start")
        services = self.client.services
        for service in services:
            self.logger.info("Service %s %s", service.uuid, service.description)
            self.jsonl.write(
                "service", uuid=service.uuid, description=service.description
            )
            for char in service.characteristics:
                self.logger.info(
                    "  Char %s handle=%s props=%s desc=%s",
                    char.uuid,
                    getattr(char, "handle", None),
                    ",".join(char.properties),
                    char.description,
                )
                self.jsonl.write(
                    "characteristic",
                    service_uuid=service.uuid,
                    uuid=char.uuid,
                    handle=getattr(char, "handle", None),
                    properties=list(char.properties),
                    description=char.description,
                )
                for desc in char.descriptors:
                    self.logger.info(
                        "    Desc %s handle=%s", desc.uuid, getattr(desc, "handle", None)
                    )
                    self.jsonl.write(
                        "descriptor",
                        characteristic_uuid=char.uuid,
                        uuid=desc.uuid,
                        handle=getattr(desc, "handle", None),
                    )
        self.jsonl.write("services_done")

    def on_notify(self, sender, data: bytearray):
        payload = bytes(data)
        decoded = decode_notification(payload)
        parsed = parse_notification(payload)
        self.logger.info("NOTIFY sender=%s data=%s decoded=%s", sender, payload.hex(), decoded)
        self.jsonl.write(
            "notify",
            sender=str(sender),
            data_hex=payload.hex(),
            decoded=decoded,
            length=len(payload),
            parsed=parsed,
        )

    def on_hid_notify(self, sender, data: bytearray):
        payload = bytes(data)
        self.logger.info("HID_NOTIFY sender=%s data=%s", sender, payload.hex())
        self.jsonl.write(
            "hid_notify",
            sender=str(sender),
            data_hex=payload.hex(),
            length=len(payload),
        )

    async def hid_scan(self):
        await self.ensure_connected()
        assert self.client
        self.logger.info("Scanning HID service/report characteristics.")
        self.jsonl.write("hid_scan_start")
        found = 0
        for service in self.client.services:
            if service.uuid.lower() != HID_SERVICE_UUID:
                continue
            self.logger.info("HID service %s", service.uuid)
            self.jsonl.write("hid_service", uuid=service.uuid)
            for char in service.characteristics:
                found += 1
                self.logger.info(
                    "  HID char uuid=%s handle=%s props=%s desc=%s",
                    char.uuid,
                    getattr(char, "handle", None),
                    ",".join(char.properties),
                    char.description,
                )
                self.jsonl.write(
                    "hid_characteristic",
                    uuid=char.uuid,
                    handle=getattr(char, "handle", None),
                    properties=list(char.properties),
                    description=char.description,
                )
                for desc in char.descriptors:
                    self.logger.info(
                        "    HID desc uuid=%s handle=%s",
                        desc.uuid,
                        getattr(desc, "handle", None),
                    )
                    self.jsonl.write(
                        "hid_descriptor",
                        characteristic_uuid=char.uuid,
                        uuid=desc.uuid,
                        handle=getattr(desc, "handle", None),
                    )
        if found == 0:
            self.logger.warning("No HID service/chars found.")
        self.jsonl.write("hid_scan_done", characteristics=found)

    def hid_notify_candidates(self):
        if not self.client:
            return []
        candidates = []
        for service in self.client.services:
            if service.uuid.lower() != HID_SERVICE_UUID:
                continue
            for char in service.characteristics:
                if "notify" not in char.properties:
                    continue
                if char.uuid.lower() in {HID_REPORT_UUID, HID_BOOT_MOUSE_INPUT_UUID}:
                    candidates.append(char)
        return candidates

    async def start_hid_notify(self):
        await self.ensure_connected()
        assert self.client
        candidates = self.hid_notify_candidates()
        if not candidates:
            self.logger.warning("No HID notify report characteristics found.")
            self.jsonl.write("hid_notify_no_candidates")
            return
        for char in candidates:
            key = f"{char.uuid}:{getattr(char, 'handle', '')}"
            if key in self.hid_notify_started:
                continue
            self.logger.info(
                "Starting HID notifications on uuid=%s handle=%s",
                char.uuid,
                getattr(char, "handle", None),
            )
            self.jsonl.write(
                "hid_notify_start",
                uuid=char.uuid,
                handle=getattr(char, "handle", None),
            )
            await self.client.start_notify(char, self.on_hid_notify)
            self.hid_notify_started.add(key)
        self.logger.info("HID notifications enabled on %d characteristic(s).", len(self.hid_notify_started))
        self.jsonl.write("hid_notify_started", count=len(self.hid_notify_started))

    async def stop_hid_notify(self):
        if not self.client or not self.hid_notify_started:
            self.logger.info("HID notifications are not enabled.")
            return
        candidates = self.hid_notify_candidates()
        for char in candidates:
            key = f"{char.uuid}:{getattr(char, 'handle', '')}"
            if key not in self.hid_notify_started:
                continue
            self.logger.info(
                "Stopping HID notifications on uuid=%s handle=%s",
                char.uuid,
                getattr(char, "handle", None),
            )
            self.jsonl.write(
                "hid_notify_stop",
                uuid=char.uuid,
                handle=getattr(char, "handle", None),
            )
            try:
                await self.client.stop_notify(char)
            except Exception as exc:
                self.logger.warning("HID stop_notify failed: %s", exc)
                self.jsonl.write(
                    "hid_notify_stop_error",
                    uuid=char.uuid,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
        self.hid_notify_started.clear()
        self.logger.info("HID notifications stopped.")
        self.jsonl.write("hid_notify_stopped")

    async def read_hid_report_map(self):
        await self.ensure_connected()
        assert self.client
        self.logger.info("Reading HID report map.")
        self.jsonl.write("hid_report_map_read_start", uuid=HID_REPORT_MAP_UUID)
        data = await self.client.read_gatt_char(HID_REPORT_MAP_UUID)
        payload = bytes(data)
        self.logger.info("HID report map length=%d hex=%s", len(payload), payload.hex())
        self.jsonl.write(
            "hid_report_map_read_done",
            uuid=HID_REPORT_MAP_UUID,
            length=len(payload),
            data_hex=payload.hex(),
        )

    async def start_notify(self):
        await self.ensure_connected()
        if self.notify_started:
            self.logger.info("Notifications already enabled.")
            return
        assert self.client
        self.logger.info("Starting notifications on %s", self.notify_char)
        self.jsonl.write("notify_start", characteristic=self.notify_char)
        await self.client.start_notify(self.notify_char, self.on_notify)
        self.notify_started = True
        self.logger.info("Notifications enabled.")
        self.jsonl.write("notify_started", characteristic=self.notify_char)

    async def stop_notify(self):
        if not self.client or not self.notify_started:
            self.logger.info("Notifications are not enabled.")
            return
        self.logger.info("Stopping notifications on %s", self.notify_char)
        self.jsonl.write("notify_stop", characteristic=self.notify_char)
        try:
            await self.client.stop_notify(self.notify_char)
        except Exception as exc:
            self.logger.warning("stop_notify failed; clearing local notify state: %s", exc)
            self.jsonl.write(
                "notify_stop_error",
                error_type=type(exc).__name__,
                error=str(exc),
            )
        finally:
            self.notify_started = False
        self.logger.info("Notifications stopped.")
        self.jsonl.write("notify_stopped", characteristic=self.notify_char)

    async def send_hex(self, payload_hex: str, label: str = "raw", response: bool = True):
        await self.ensure_connected()
        if not self.notify_started:
            await self.start_notify()
        assert self.client

        payload = hex_to_bytes(payload_hex)
        decoded = decode_notification(payload)
        self.logger.info(
            "WRITE label=%s char=%s response=%s data=%s decoded_guess=%s",
            label,
            self.write_char,
            response,
            payload.hex(),
            decoded,
        )
        self.jsonl.write(
            "write_start",
            label=label,
            characteristic=self.write_char,
            response=response,
            data_hex=payload.hex(),
            decoded_guess=decoded,
        )
        await self.client.write_gatt_char(self.write_char, payload, response=response)
        self.logger.info("WRITE done label=%s", label)
        self.jsonl.write("write_done", label=label, data_hex=payload.hex())

    async def send_command(self, name: str):
        if name not in COMMANDS:
            raise ValueError(f"unknown command: {name}")
        await self.send_hex(COMMANDS[name], label=name)

    async def read_battery(self):
        await self.ensure_connected()
        assert self.client
        self.logger.info("Reading standard BLE Battery Level characteristic.")
        self.jsonl.write("battery_read_start", characteristic=BATTERY_CHAR_UUID)
        data = await self.client.read_gatt_char(BATTERY_CHAR_UUID)
        level = data[0] if data else None
        self.logger.info("Battery level: %s%% raw=%s", level, bytes(data).hex())
        self.jsonl.write(
            "battery_read_done",
            characteristic=BATTERY_CHAR_UUID,
            level=level,
            data_hex=bytes(data).hex(),
        )

    async def sync_time(self):
        payload = build_time_sync_payload()
        parsed = parse_notification(payload)
        self.logger.info(
            "Sending time sync: timestamp_utc=%s tz=%s",
            parsed.get("timestamp_utc"),
            parsed.get("timezone_offset_hours"),
        )
        await self.send_hex(payload.hex(), label="time_sync")

    async def activity_query(self):
        self.logger.info("Requesting current activity/steps packet.")
        self.jsonl.write("activity_query_start")
        await self.send_command("activity_query")
        await self.logged_sleep(2.0, "activity_query_wait")
        self.jsonl.write("activity_query_done")

    async def sync_baseline(self):
        self.logger.info("Running lightweight app-style sync baseline.")
        self.jsonl.write("sync_baseline_start")
        await self.send_command("status")
        await self.sync_time()
        await self.send_command("locale_en_us")
        await self.send_command("activity_query")
        await self.logged_sleep(2.0, "sync_baseline_activity_wait")
        self.jsonl.write("sync_baseline_done")

    async def history_query(self):
        self.logger.info("Requesting history summary and measurement stream.")
        self.jsonl.write("history_query_start")
        await self.send_command("history_summary_query")
        await self.logged_sleep(2.0, "history_summary_wait")
        await self.send_command("history_measurement_query")
        await self.logged_sleep(5.0, "history_measurement_wait")
        self.jsonl.write("history_query_done")

    async def sleep_query(self):
        self.logger.info("Requesting sleep/history timeline packets.")
        self.jsonl.write("sleep_query_start")
        await self.send_command("sleep_history_query")
        await self.logged_sleep(3.0, "sleep_history_wait")
        self.jsonl.write("sleep_query_done")

    async def run_spo2(self, seconds: float):
        self.logger.info("Running SpO2 for %.1fs", seconds)
        self.jsonl.write("spo2_sequence_start", seconds=seconds)
        await self.send_command("spo2_start")
        await asyncio.sleep(seconds)
        await self.send_command("spo2_stop")
        self.jsonl.write("spo2_sequence_done", seconds=seconds)

    async def run_hr(self, seconds: float):
        self.logger.info("Running HR for %.1fs", seconds)
        self.jsonl.write("hr_sequence_start", seconds=seconds)
        await self.send_command("hr_start")
        await asyncio.sleep(seconds)
        await self.send_command("hr_stop")
        self.jsonl.write("hr_sequence_done", seconds=seconds)

    async def find_test(self):
        self.logger.info("Sending find-ring candidate 04 command.")
        self.jsonl.write("find_test_start", candidate="04")
        await self.send_command("find_candidate_04")
        self.jsonl.write("find_test_done", candidate="04")

    async def mode_test(self, mode: str):
        if mode not in {"1", "2", "reset"}:
            raise ValueError("mode must be 1, 2, or reset")
        name = {
            "1": "mode_candidate_52_01",
            "2": "mode_candidate_52_02",
            "reset": "mode_candidate_52_reset",
        }[mode]
        self.logger.info("Sending mode candidate command: %s", name)
        await self.send_command(name)

    async def logged_sleep(self, seconds: float, label: str):
        self.logger.info("Sleeping %.1fs for %s; notifications remain active.", seconds, label)
        self.jsonl.write("sleep_start", seconds=seconds, label=label)
        await asyncio.sleep(seconds)
        self.jsonl.write("sleep_done", seconds=seconds, label=label)

    async def phase2_test(self):
        """Run known-variant tests with conservative waits between commands."""
        await self.ensure_connected()
        if not self.notify_started:
            await self.start_notify()

        self.logger.info("Starting Phase 2 known-variant test.")
        self.jsonl.write("phase2_start")

        steps = [
            ("find_duration_1s_candidate", "0401000000000000000000000000000000000000", 5.0),
            ("find_duration_5s_candidate", "0405000000000000000000000000000000000000", 8.0),
            ("find_duration_10s_confirmed", "040a000000000000000000000000000000000000", 12.0),
            ("find_duration_20s_candidate", "0414000000000000000000000000000000000000", 20.0),
            ("spo2_start_direct", "2301000000000000000000000000000000000000", 10.0),
            ("spo2_stop_direct", "2300000000000000000000000000000000000000", 5.0),
            ("hr_start_direct", "14b4000000000000000000000000000000000000", 10.0),
            ("hr_stop_direct", "1500000000000000000000000000000000000000", 5.0),
        ]

        for label, payload_hex, wait_seconds in steps:
            self.logger.info("Phase 2 step: %s", label)
            self.jsonl.write("phase2_step_start", label=label, data_hex=payload_hex)
            await self.send_hex(payload_hex, label=f"phase2_{label}")
            await self.logged_sleep(wait_seconds, f"phase2_{label}")
            self.jsonl.write("phase2_step_done", label=label, data_hex=payload_hex)

        self.logger.info("Phase 2 known-variant test done.")
        self.jsonl.write("phase2_done")

    def print_help(self):
        print(
            """
Commands:
  help                         Show this help.
  scan [seconds]               Scan for BLE devices and auto-select SMART_RING.
  connect [address]            Connect to selected ring, or specific address/UUID.
  disconnect                   Disconnect.
  services                     Print discovered services/chars.
  notify on                    Enable notifications on 0x33f4.
  notify off                   Disable notifications.
  hid scan                     Print HID service/report characteristics.
  hid on                       Enable HID report notifications.
  hid off                      Disable HID report notifications.
  hid map                      Read raw HID report map.

  battery                      Read standard BLE battery percentage.
  status                       Send device/status query.
  time sync                    Send app-style current time/timezone command.
  locale                       Send en-US locale command.
  activity                     Request current steps/activity packet.
  sync baseline                Send status, time sync, locale, activity query.
  history                      Request history summary and measurement stream.
  sleep                        Request sleep/history timeline packets.
  spo2 start                   Start SpO2 measurement.
  spo2 stop                    Stop SpO2 measurement.
  spo2 run [seconds]           Start SpO2, wait, stop. Default 25s.
  hr start                     Start HR measurement.
  hr stop                      Stop/cleanup HR measurement.
  hr run [seconds]             Start HR, wait, stop. Default 30s.

  selfie on                    Enable selfie/clench mode.
  selfie off                   Disable selfie/clench mode.
  find                         Send possible find-ring 04 0a command.
  mode 1                       Send 52...01 candidate.
  mode 2                       Send 52...02 candidate.
  mode reset                   Send 52...ffffffff reset candidate.
  phase2                       Run known-variant test sequence automatically.

  raw <hex>                    Send any hex payload to write char.
  sleep <seconds>              Wait while notifications keep logging.
  quit                         Disconnect and exit.
"""
        )

    async def repl(self):
        self.print_help()
        while True:
            try:
                line = await asyncio.to_thread(input, "ring> ")
            except EOFError:
                line = "quit"

            line = line.strip()
            if not line:
                continue

            self.jsonl.write("user_command", line=line)
            parts = line.split()
            cmd = parts[0].lower()

            try:
                if cmd in {"quit", "exit"}:
                    await self.disconnect()
                    return
                if cmd == "help":
                    self.print_help()
                elif cmd == "scan":
                    timeout = float(parts[1]) if len(parts) > 1 else 10.0
                    await self.scan(timeout)
                elif cmd == "connect":
                    target = parts[1] if len(parts) > 1 else None
                    await self.connect(target)
                elif cmd == "disconnect":
                    await self.disconnect()
                elif cmd == "services":
                    await self.services()
                elif cmd == "notify" and len(parts) > 1 and parts[1] == "on":
                    await self.start_notify()
                elif cmd == "notify" and len(parts) > 1 and parts[1] == "off":
                    await self.stop_notify()
                elif cmd == "hid" and len(parts) > 1 and parts[1] == "scan":
                    await self.hid_scan()
                elif cmd == "hid" and len(parts) > 1 and parts[1] == "on":
                    await self.start_hid_notify()
                elif cmd == "hid" and len(parts) > 1 and parts[1] == "off":
                    await self.stop_hid_notify()
                elif cmd == "hid" and len(parts) > 1 and parts[1] == "map":
                    await self.read_hid_report_map()
                elif cmd == "battery":
                    await self.read_battery()
                elif cmd == "status":
                    await self.send_command("status")
                elif cmd == "time" and len(parts) > 1 and parts[1] == "sync":
                    await self.sync_time()
                elif cmd == "locale":
                    await self.send_command("locale_en_us")
                elif cmd == "activity":
                    await self.activity_query()
                elif cmd == "sync" and len(parts) > 1 and parts[1] == "baseline":
                    await self.sync_baseline()
                elif cmd == "history":
                    await self.history_query()
                elif cmd == "sleep" and len(parts) == 1:
                    await self.sleep_query()
                elif cmd == "spo2" and len(parts) > 1 and parts[1] == "start":
                    await self.send_command("spo2_start")
                elif cmd == "spo2" and len(parts) > 1 and parts[1] == "stop":
                    await self.send_command("spo2_stop")
                elif cmd == "spo2" and len(parts) > 1 and parts[1] == "run":
                    seconds = float(parts[2]) if len(parts) > 2 else 25.0
                    await self.run_spo2(seconds)
                elif cmd == "hr" and len(parts) > 1 and parts[1] == "start":
                    await self.send_command("hr_start")
                elif cmd == "hr" and len(parts) > 1 and parts[1] == "stop":
                    await self.send_command("hr_stop")
                elif cmd == "hr" and len(parts) > 1 and parts[1] == "run":
                    seconds = float(parts[2]) if len(parts) > 2 else 30.0
                    await self.run_hr(seconds)
                elif cmd == "selfie" and len(parts) > 1 and parts[1] == "on":
                    await self.send_command("selfie_start")
                elif cmd == "selfie" and len(parts) > 1 and parts[1] == "off":
                    await self.send_command("selfie_stop")
                elif cmd == "find":
                    await self.find_test()
                elif cmd == "mode" and len(parts) > 1:
                    await self.mode_test(parts[1])
                elif cmd == "phase2":
                    await self.phase2_test()
                elif cmd == "raw" and len(parts) > 1:
                    await self.send_hex("".join(parts[1:]), label="raw")
                elif cmd == "sleep" and len(parts) > 1:
                    seconds = float(parts[1])
                    await self.logged_sleep(seconds, "manual")
                else:
                    self.logger.warning("Unknown command: %s", line)
                    self.print_help()
            except (BleakError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                self.logger.exception("Command failed: %s", line)
                self.jsonl.write(
                    "command_error",
                    line=line,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )


async def async_main():
    parser = argparse.ArgumentParser(description="Interactive SMART_RING BLE tester")
    parser.add_argument("--log-dir", default="logs", help="directory for verbose logs")
    parser.add_argument("--address", help="connect to a known Bleak address/UUID on startup")
    parser.add_argument("--no-autoscan", action="store_true", help="do not scan on startup")
    args = parser.parse_args()

    logger, jsonl = setup_logging(Path(args.log_dir))
    cli = SmartRingCli(logger, jsonl)

    try:
        if args.address:
            try:
                await cli.connect(args.address)
                await cli.start_notify()
            except (BleakError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                logger.error("Startup connect failed for %s: %s", args.address, exc)
                jsonl.write(
                    "startup_connect_error",
                    address=args.address,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                logger.info("Continuing to interactive CLI. Try: scan")
        elif not args.no_autoscan:
            await cli.scan()
        await cli.repl()
    finally:
        jsonl.write("log_end")
        jsonl.close()


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print()
        print("Interrupted.")


if __name__ == "__main__":
    main()
