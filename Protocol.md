# SMART_RING BLE Protocol

Reverse-engineered BLE protocol notes for a cheap JRING-compatible smart ring
advertising as `SMART_RING`.

This document is intended as an implementer reference. It describes the BLE
identity, GATT transport, command payloads, expected responses, and uncertainty
markers. Chronological evidence lives in `lab-notes.md` and
`ring-protocol-notes.md`.

## Status Markers

- `CONFIRMED`: tested from the Python CLI or matched against app-visible data.
- `PARTIAL`: packet is known, but one or more fields are not fully decoded.
- `UNCONFIRMED`: plausible interpretation from limited captures.
- `UNKNOWN`: observed traffic with no reliable meaning yet.

## Device Identity

Status: `CONFIRMED`

```text
Advertised name:          SMART_RING
Advertising service UUID: 0000fef5-0000-1000-8000-00805f9b34fb
Manufacturer ID:          0x594a
Manufacturer data:        41422ec75b6a7a003a001600
Embedded ring address:    41:42:2e:c7:5b:6a
```

The first six bytes of the manufacturer data match the ring address observed in
sniffer captures:

```text
41 42 2e c7 5b 6a
```

On macOS/Bleak, the address shown to Python is a CoreBluetooth UUID rather than
the real BLE address. One observed UUID was:

```text
2125B1FC-3067-2D98-889E-F89D13C4BEFC
```

Do not hard-code that UUID for other machines or after Bluetooth reset/forget
operations.

## GATT Layout

Status: `CONFIRMED`

The main app protocol uses service `0x56ff`.

```text
Service UUID: 000056ff-0000-1000-8000-00805f9b34fb

Write characteristic:
  UUID:       000033f3-0000-1000-8000-00805f9b34fb
  Handle:     0x0017
  Properties: write
  Direction:  central -> ring

Notify characteristic:
  UUID:       000033f4-0000-1000-8000-00805f9b34fb
  Handle:     0x0019
  Properties: notify
  Direction:  ring -> central

CCCD:
  Handle:     0x001a
```

Other observed services:

```text
0000fef5-0000-1000-8000-00805f9b34fb  custom/vendor service
0000ff12-0000-1000-8000-00805f9b34fb  custom/vendor service, unexplored
0000180f-0000-1000-8000-00805f9b34fb  Battery Service
0000180a-0000-1000-8000-00805f9b34fb  Device Information
00001812-0000-1000-8000-00805f9b34fb  HID, seen in phone sniffs, not exposed by Bleak/macOS
```

`0xff12` has not been decoded yet:

```text
0000ff15-0000-1000-8000-00805f9b34fb  write-without-response, read
0000ff14-0000-1000-8000-00805f9b34fb  notify
```

## Connection Flow

Status: `CONFIRMED`

```text
1. Scan for name SMART_RING or manufacturer data prefix 41422ec75b6a.
2. Connect.
3. Discover service 0x56ff.
4. Enable notifications on 0x33f4.
5. Write 20-byte commands to 0x33f3.
6. Decode 20-byte notifications from 0x33f4.
```

Some attributes require pairing/encryption. Phone captures showed SMP pairing
and link encryption before protected reads.

## Packet Format

Status: `CONFIRMED`

Most app protocol packets are fixed 20-byte payloads:

```text
byte 0      command / response id
bytes 1-19  payload fields and zero padding
```

Multi-byte integer fields observed so far are little-endian:

```text
u32 Unix timestamp
u32 steps
u32 distance-like units
u32 calories
```

There is no observed Oura-style frame header such as:

```text
[command][length][payload]
```

Instead, the first byte is the command ID and the packet is padded to 20 bytes.

## Commands

### Time Sync

Status: `CONFIRMED`

Write:

```text
01 TT TT TT TT ZZ 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Fields:

```text
byte 0       0x01
bytes 1-4    Unix timestamp, u32 little-endian
byte 5       signed timezone offset hours
bytes 6-19   zero padding
```

Example:

```text
019edc156afc0000000000000000000000000000
```

Expected notify:

```text
same 20-byte payload echoed back
```

### Locale

Status: `CONFIRMED`

Write:

```text
21656e2d55530000000000000000000000000000
```

Decoded:

```text
byte 0       0x21
bytes 1-5    ASCII "en-US"
bytes 6-19   zero padding
```

Expected notify:

```text
same 20-byte payload echoed back
```

### Status

Status: `CONFIRMED`

Write:

```text
0c00000000000000000000000000000000000000
```

Expected notify:

```text
0c7a0041422ec75b6a3a001600..............
```

Observed fields:

```text
byte 0       0x0c
bytes 3-8    embedded ring address, e.g. 41 42 2e c7 5b 6a
```

Other fields in the status response are not decoded.

### Current Activity Query

Status: `CONFIRMED`

Write:

```text
0299b85a00000000000000000000000000000000
```

Expected notifications:

```text
02...        query acknowledgement
03...        current activity packet
13...        companion activity summary packet
```

The bytes after `0x02` are not fully understood. They may be a timestamp,
nonce, or query parameter.

### Current Activity Response

Status: `CONFIRMED`

Notify:

```text
03 TT TT TT TT SS SS SS SS DD DD DD DD CC CC CC CC 00 00 00
```

Fields:

```text
byte 0       0x03
bytes 1-4    Unix timestamp, u32 little-endian
bytes 5-8    steps, u32 little-endian
bytes 9-12   distance-like units, u32 little-endian
bytes 13-16  calories, u32 little-endian
bytes 17-19  unknown / padding
```

Distance appears to be approximately meters. The app displayed `0.28 km` for
`287` distance units and `0.10 km` for `105` distance units.

Example:

```text
03fd7c156a480100001f01000012000000504600
```

Decoded:

```text
timestamp:      2026-05-26
steps:          328
distance units: 287
calories:       18
```

### Activity Summary Response

Status: `PARTIAL`

Notify:

```text
13 TT TT TT TT AA AA AA AA BB BB BB BB SS SS SS SS 00 00 00
```

Known/likely fields:

```text
byte 0       0x13
bytes 1-4    Unix timestamp, u32 little-endian
bytes 5-8    unknown field A
bytes 9-12   unknown field B
bytes 13-16  step-like summary field
```

This packet usually appears with `0x03`. The field at bytes `13-16` sometimes
matches a step-like total or summary value, but the exact relationship to the
app display is not fully decoded.

### Goal / Step Goal

Status: `CONFIRMED`

Write:

```text
1a10270000000000000000000000000000000000
```

Fields:

```text
byte 0       0x1a
bytes 1-4    goal value, u32 little-endian
```

`0x00002710` is decimal `10000`, matching the app's daily step goal.

Expected notify:

```text
same 20-byte payload echoed back
```

### Battery

Status: `CONFIRMED`

Use the standard BLE Battery Service, not the custom app protocol.

```text
Service: 0000180f-0000-1000-8000-00805f9b34fb
Char:    00002a19-0000-1000-8000-00805f9b34fb
Format:  uint8 percent
```

Example:

```text
0x64 = 100%
```

### Live Heart Rate Start

Status: `CONFIRMED`

Write:

```text
14b4000000000000000000000000000000000000
```

Expected notify:

```text
14b4000000000000000000000000000000000000
```

Then the ring sends `0x14` heart-rate result packets.

### Live Heart Rate Result

Status: `CONFIRMED`

Notify:

```text
14 TT TT TT TT HR 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Fields:

```text
byte 0       0x14
bytes 1-4    changing field, likely timestamp or measurement counter
byte 5       BPM
bytes 6-19   zero padding / unknown
```

Examples:

```text
14bbec146a500000000000000000000000000000  -> 80 bpm
14c0ec146a510000000000000000000000000000  -> 81 bpm
1410ef146a550000000000000000000000000000  -> 85 bpm
```

The app-visible BPM values matched byte `5`.

### Live Heart Rate Complete / Stop

Status: `CONFIRMED`

Completion/status notify:

```text
2700000000000000000000000000000000000000
```

Stop write:

```text
1500000000000000000000000000000000000000
```

Expected stop notify:

```text
1500000000000000000000000000000000000000
```

### SpO2 Start

Status: `CONFIRMED`

Write:

```text
2301000000000000000000000000000000000000
```

Expected notify:

```text
2301000000000000000000000000000000000000
```

### SpO2 Progress

Status: `CONFIRMED`

Notify, repeated while measuring:

```text
2400000000000000000000000000000000000000
```

SpO2 needs a long enough run to produce a final value. Short runs may only emit
progress and stop/status packets.

### SpO2 Result

Status: `CONFIRMED`

Notify:

```text
24 ?? ?? ?? O2 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Known field:

```text
byte 4       SpO2 percentage
```

Examples:

```text
245e774d63050000000000000000000000000000  -> 99%
24536c4261050000000000000000000000000000  -> 97%
```

### SpO2 Stop

Status: `CONFIRMED`

Write:

```text
2300000000000000000000000000000000000000
```

Expected notify:

```text
2300000000000000000000000000000000000000
```

Additional completion/status notifications may follow:

```text
2800000000000000000000000000000000000000
```

Meaning of `0x28` in this context is not fully decoded.

### Sleep / History Query

Status: `CONFIRMED`

Write:

```text
1000000000000000000000000000000000000000
```

Expected notifications:

```text
10...        history summary packets
11...        sleep timeline packets
```

The same command is currently used by the CLI for sleep/history timeline pulls.

### Sleep Timeline

Status: `CONFIRMED`

Notify:

```text
11 TT TT TT TT S0 S1 S2 S3 S4 S5 S6 S7 S8 S9 S10 S11 S12 S13 S14
```

Fields:

```text
byte 0       0x11
bytes 1-4    Unix timestamp, u32 little-endian
bytes 5-19   15 sleep-stage samples, one minute each
```

Known sample values:

```text
0x28  light sleep
0x63  deep sleep
0x00  empty/no data, observed in code handling but not yet app-matched as awake
```

Morning capture matched the app:

```text
20 packets * 15 samples = 300 minutes = 5h00m
18 light blocks = 270 minutes = 4h30m
2 deep blocks = 30 minutes = 0h30m
```

Awake duration was `0h00m` in the app, so the awake sample value is still not
confirmed.

### History / Stored Measurement Query

Status: `PARTIAL`

Write:

```text
1600000000000000000000000000000000000000
```

Expected notifications:

```text
16f0...      header or stream marker
16aa...      metadata
16a0...      sample chunk
16ff...      completion / end marker
```

Known parsing:

```text
0x16 0xaa     metadata-like record
0x16 0xa0     sample chunk, contains historical HR-like values
```

Historical sample chunks have contained values matching app HR history, but the
full record structure is not fully decoded.

### Selfie Mode

Status: `CONFIRMED`

Enable write:

```text
0701000000000000000000000000000000000000
```

Expected notify:

```text
0701000000000000000000000000000000000000
```

Ring clench/shutter event notify:

```text
0602000000000000000000000000000000000000
```

Disable write:

```text
0700000000000000000000000000000000000000
```

Expected notify:

```text
0700000000000000000000000000000000000000
```

### Find Ring

Status: `CONFIRMED`

Write:

```text
040a000000000000000000000000000000000000
```

Expected notify:

```text
040a000000000000000000000000000000000000
```

Other tested variants were accepted/echoed:

```text
0401000000000000000000000000000000000000
0405000000000000000000000000000000000000
040a000000000000000000000000000000000000
0414000000000000000000000000000000000000
```

`byte 1` is likely a duration or intensity parameter, but that is not fully
confirmed.

### Automatic Heart-Rate Schedule

Status: `CONFIRMED`

Disable automatic HR:

```text
190000173b001e02000000000000000000000000
```

Enable automatic HR, 30-minute cadence:

```text
190000173b011e02000000000000000000000000
```

Enable automatic HR, likely 10-minute cadence:

```text
190000173b010a02000000000000000000000000
```

Fields:

```text
byte 0       0x19
bytes 1-2    start time, HH MM; 00 00 = 00:00
bytes 3-4    end time, HH MM; 17 3b = 23:59
byte 5       enable flag; 00 = off, 01 = on
byte 6       cadence minutes; 1e = 30, 0a = 10
byte 7       unknown mode/type, observed as 02
bytes 8-19   zero padding / unknown
```

Expected notify:

```text
same 20-byte payload echoed back
```

### Factory Reset

Status: `CONFIRMED`

Write:

```text
0efedcba98765432100000000000000000000000
```

Fields:

```text
byte 0       0x0e
bytes 1-8    magic value: fe dc ba 98 76 54 32 10
bytes 9-19   zero padding
```

Expected behavior:

```text
No app-protocol acknowledgement was captured.
Connection may drop/reconnect.
Activity counters reset to zero.
BLE address and GATT layout did not change in testing.
```

### Air Control / HID Mode

Status: `UNCONFIRMED`

The phone app's air-control feature appears related to BLE HID. Phone captures
showed HID service `0x1812` with media-control and pointer-like reports:

```text
next/previous track
volume up/down
mute
play/pause
touch pad
mouse/pointer
wheel
X/Y
buttons
```

Custom app writes observed around air-control testing:

```text
5200000000010000000000000000000000000000
5200000000020000000000000000000000000000
5200000000ffffffff0000000000000000000000
```

Working hypothesis:

```text
52...01         enable one air-control/HID mode
52...02         enable another air-control/HID mode
52...ffffffff   exit/reset air-control/HID mode
```

The CLI can write these commands, but macOS/Bleak did not expose the HID service
or HID notifications. This may be due to CoreBluetooth hiding or owning BLE HID
services, or because the ring exposes HID only in a different mode/connection
state.

Related `0x1b` config variant:

```text
1b01010000000900110000000050000000000000  usual observed value
1b01010000000900110000010050000000000000  appeared around air-control testing
```

The changed byte may be an air-control flag. This is not confirmed.

## Unknown / Partially Decoded Notifications

### `0x0b` Percent-Like Status

Status: `UNKNOWN`

Example:

```text
0b63000000000000000000000000000000000000
```

Byte `1` is percent-like:

```text
0x63 = 99
```

This may be battery, health/status, or another percentage-like field. It is not
confirmed. Standard Battery Service should be preferred for actual battery
percentage.

### `0x20` Device Time / Config

Status: `PARTIAL`

Example:

```text
2062e80728090abebb0000000000000000000000
```

This appears during notification startup. The CLI labels it as a device
time/config response, but fields are not decoded.

### `0xf6` Identity / Config Chunks

Status: `PARTIAL`

Examples:

```text
f60000007a001600000000000000000000000000
f641422ec75b6a00000000000000000000000000
```

The second example embeds the ring address after the command byte:

```text
41 42 2e c7 5b 6a
```

The rest is not decoded.

### `0x44`

Status: `UNKNOWN`

Observed during app sync/config traffic. It may contain date/profile/schedule
configuration. Not decoded.

### `0x48`

Status: `PARTIAL`

Appears to carry an app/client identifier string in some captures. Not required
for current CLI control.

## Implementation Notes

Recommended minimum client sequence:

```text
scan for SMART_RING or manufacturer prefix 41422ec75b6a
connect
enable notify on 000033f4-0000-1000-8000-00805f9b34fb
write commands to 000033f3-0000-1000-8000-00805f9b34fb
parse 20-byte notifications
```

Useful first commands after connecting:

```text
status
time sync
locale en-US
activity query
battery read
```

For live measurements:

```text
HR:    write 14b4..., wait for 0x14 BPM packets, then write 1500...
SpO2:  write 2301..., wait 35-45 seconds, then write 2300...
```

Short SpO2 runs may not produce a final `0x24` result packet.

## Open Questions

- Full meaning of `0x13` activity summary fields.
- Exact units and rounding rules for distance/mileage.
- Calorie calculation versus app display goals.
- Awake sleep sample value.
- Full historical HR/SpO2 record format in `0x16` streams.
- Meaning of `0x0b`, `0x20`, `0x44`, `0x48`, and `0xf6`.
- Whether `0x52` and the `0x1b` variant fully control air/HID mode.
- Whether HID can be accessed outside the official app on macOS, or requires
  another BLE stack / OS HID API.
