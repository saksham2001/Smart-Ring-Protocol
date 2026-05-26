# SMART_RING BLE Protocol Notes

Source captures: `ring-pair5.pcapng`, `ring-pair6.pcapng`, `ring-pair7.pcapng`, `ring-pair8.pcapng`, `logs/smart-ring-20260526-011251.jsonl`, `logs/smart-ring-20260526-014557.jsonl`

## Layout

This document is split into:

- `Reference`: stable facts needed to talk to the ring.
- `Command Reference`: decoded and partially decoded app commands.
- `Capture Evidence`: chronological notes showing how each command was inferred.
- `Sniffing Notes`: useful Wireshark filters and capture workflow notes.

## Reference

### Hardware Notes

Original order listing: `https://www.aliexpress.us/item/3256810466598469.html`

Important caveat: AliExpress sellers often reuse or edit the same listing across batches. The physical ring under test does not appear to have an OLED/display. Treat the listing specs as weak hardware clues, not proof.

Seller-provided specs:

```text
Material: 304 stainless steel, glue pouring process
Main chip: Coolchip AB2026
Memory: 64KB + 8K cache + 8Mbit flash
Bluetooth: 5.4
Charging time: 2 hours
Runtime: 3-5 days normal use
Charging: magnetic charging
Compatibility: Android 9.0+, iOS 10.0+
Sizes: 7-13
Thickness: 2.5 mm
```

Earlier DA14585 notes came from similar JRING/SR08/TK9 listings, including some display-ring variants. Those are useful context for the broader cheap JRING-compatible ecosystem, but they are not confirmed for this non-display ring. The reliable facts for this project are the BLE identity, GATT service/characteristics, and decoded command traffic.

Public listings for similar AB2026B3 smart rings often mention `HX3918` / `TYHX HR3918` optical heart-rate sensors and `SC7A20H` or similar 3-axis accelerometers. Treat those as likely-nearby hardware families, not confirmed for this exact ring unless the case is opened or the firmware/device info exposes the parts.

### Device Identity

- Advertised name: `SMART_RING`
- BLE advertising address: `41:42:2e:c7:5b:6a`
- Advertising type: `ADV_IND` (connectable)
- Advertising service UUID: `0xfef5`
- Advertising manufacturer ID: `0x594a`
- Advertising manufacturer data: `41422ec75b6a7a003a001600`

The first 6 bytes of the manufacturer data match the BLE address:

```text
41 42 2e c7 5b 6a
```

### Successful Connection

- Valid `CONNECT_IND` frame: `1848`
- Capture time: `108.334135s`
- Central / initiator address: redacted
- Ring / advertiser address: `41:42:2e:c7:5b:6a`
- Connection access address: `0x50654c62`

### GATT Services

Observed GATT services:

```text
0xfef5  custom / Dialog-ish service
0x56ff  custom app protocol service
0xff12  custom service
0x1800  GAP
0x1801  GATT
0x180f  Battery
0x180a  Device Information
0x1812  HID
```

The app protocol appears to use service `0x56ff`.

### App Transport

Service: `0x56ff`

```text
Handle 0x0017
Characteristic UUID: 0x33f3
Properties: Write
Direction: central/app -> ring
Purpose: command writes

Handle 0x0019
Characteristic UUID: 0x33f4
Properties: Notify
Direction: ring -> central/app
Purpose: responses and measurement data

Handle 0x001a
Descriptor: CCCD for 0x33f4
Purpose: enable notifications
```

Full UUIDs used successfully from Python/Bleak:

```text
Service:     000056ff-0000-1000-8000-00805f9b34fb
Write char:  000033f3-0000-1000-8000-00805f9b34fb
Notify char: 000033f4-0000-1000-8000-00805f9b34fb
```

Typical client flow:

```text
1. Connect to SMART_RING.
2. Discover service 0x56ff.
3. Enable notifications on characteristic 0x33f4 / handle 0x0019.
4. Write commands to characteristic 0x33f3 / handle 0x0017.
5. Parse notifications from handle 0x0019.
```

### Packet Shape

Most custom app protocol payloads are 20 bytes:

```text
[command_id:1] [payload / parameters / padding:19]
```

The ring does not appear to use the Oura-style `[tag][payload_length][payload]` frame. Instead, command IDs and response IDs usually reuse the first byte directly, with fixed-size zero padding.

Multi-byte values observed so far are little-endian:

```text
u32 timestamp: 4 bytes little-endian Unix seconds
u32 steps:     4 bytes little-endian
u32 distance:  4 bytes little-endian
u32 calories:  4 bytes little-endian
```

### Pairing / Encryption

The ring requires encryption for at least some attributes. In the capture, reading HID report map initially returns:

```text
Error Response - Insufficient Encryption
```

Then pairing starts:

```text
SMP Pairing Request
SMP Pairing Response
Pairing Confirm
Pairing Random
LL_ENC_REQ / LL_ENC_RSP
LL_START_ENC_REQ / LL_START_ENC_RSP
key exchange
```

## Command Reference

Most app protocol payloads are 20 bytes.

### Summary

```text
01...        time sync
02...        current activity query, triggers 0x03 / 0x13
03...        current activity response: timestamp, steps, distance-like units, calories
04...        find-ring light command
06...        selfie/clench event from ring
07...        selfie mode on/off
0e...        factory reset command, magic payload observed
0b...        percent-like status, possibly battery/status
0c...        status/device query
10...        sleep/history query
11...        sleep timeline response
13...        activity summary response, partially decoded
14...        live HR start/result
15...        HR stop/cleanup
16...        historical measurement stream query/response
19...        automatic HR schedule/config
1a...        goal/config, includes 10000 step goal
20...        device time/config
21...        locale/language
23...        SpO2 start/stop
24...        SpO2 progress/final result
27...        measurement completion/status
28...        SpO2 completion/status marker
44...        unknown profile/date/config, possible schedule/config
48...        app/client identifier
52...        air-control/HID mode candidate
f6...        identity/config chunks
```

### Device / Status Query

Write:

```text
0c00000000000000000000000000000000000000
```

Notification:

```text
0c7a0041422ec75b6a3a0016007379373725f4f7
```

This response includes the ring address:

```text
41 42 2e c7 5b 6a
```

### Locale / Language

Write:

```text
21656e2d55530000000000000000000000000000
```

Payload after command byte `0x21` is ASCII:

```text
en-US
```

### Factory Reset

Observed when factory reset was pressed in the JRING app:

```text
0efedcba98765432100000000000000000000000
```

This is command `0x0e` followed by an obvious magic value:

```text
fe dc ba 98 76 54 32 10
```

No app-protocol notification was captured for this write. Shortly after the write, the connection ended and the app reconnected. On reconnect the activity packets were reset to zero:

```text
032d90156a000000000000000000000000000000
132d90156a000000000000000000000000000000
```

The BLE address and GATT layout did not change after reset. This looks like an app/user-data reset rather than a firmware or BLE identity reset.

### Automatic HR Schedule

Focused settings changes in `ring-pair9.pcapng` confirmed command `0x19` is the automatic HR test schedule/config command.

Automatic HR off:

```text
190000173b001e02000000000000000000000000
```

Automatic HR on:

```text
190000173b011e02000000000000000000000000
```

Likely structure:

```text
byte 0       command ID: 0x19
bytes 1-2    start time: 00:00
bytes 3-4    end time: 17 3b = 23:59
byte 5       enable flag: 00 off, 01 on
byte 6       cadence minutes: 1e = 30
byte 7       unknown mode/type: 02
bytes 8-19   padding / unknown
```

This matches the app setting: 30-minute cadence from 12:00 AM to 11:59 PM.

### Air Control / HID Mode

The ring exposes a HID service (`0x1812`) with a report map that includes consumer-control and pointer-like capabilities:

```text
Scan Next Track
Scan Previous Track
Volume Increment
Volume Decrement
Mute
Play/Pause
Touch Pad
Mouse / Pointer
Wheel
X / Y
Buttons
```

This strongly suggests the app's "air control" feature uses BLE HID reports for media and pointer gestures, not only the custom `0x56ff` app protocol.

The custom app writes around air-control testing were `0x52` variants:

```text
5200000000010000000000000000000000000000
5200000000020000000000000000000000000000
5200000000ffffffff0000000000000000000000
```

Working hypothesis:

```text
52...01         enter/enable one HID/air-control mode
52...02         enter/enable another HID/air-control mode
52...ffffffff   exit/reset HID/air-control mode
```

This still needs a focused test while using music/video controls and watching HID report notifications on handles `0x0039`, `0x003d`, `0x0041`, `0x0045`, or `0x0049`.

One `0x1b` config variant also appeared in this run:

```text
1b01010000000900110000010050000000000000
```

The usual sync value is:

```text
1b01010000000900110000000050000000000000
```

The changed byte may be an air-control enable/config flag, but this is not confirmed because the capture also contained normal app resync traffic.

### Likely Start HR / Measurement Stream

Write:

```text
1601000000000000000000000000000000000000
```

Observed after this write: many `0x16...` notifications, including sample chunks.

### Likely Stop HR / Measurement Stream

Write:

```text
1600000000000000000000000000000000000000
```

Notification:

```text
16ff000000000000000000000000000000000000
```

This appears to acknowledge stream stop / completion.

### Live Heart Rate

The app showed BPM values `80` and `81`. These match later `0x14...` notifications:

```text
14bbec146a500000000000000000000000000000
14c0ec146a510000000000000000000000000000
14c2ec146a500000000000000000000000000000
```

Interpretation:

```text
0x50 = 80 bpm
0x51 = 81 bpm
```

So, for `0x14` notifications, byte 5 appears to contain the BPM value:

```text
14 bb ec 14 6a 50 ...
               ^^ 0x50 = 80 bpm

14 c0 ec 14 6a 51 ...
               ^^ 0x51 = 81 bpm
```

This byte index should be verified with more captures at different heart rates.

## Capture Evidence

### Ring Pair5: First Confirmed Heart Rate

First good capture with app writes and notifications. Confirmed `0x14` live heart-rate packets by matching app-visible values `80` and `81`.

### Ring Pair6 Findings

Source capture: `ring-pair6.pcapng`

This capture included pairing, SpO2 measurement, HR measurement, find-ring, selfie mode, and some idle/background traffic.

#### Pair6 Connection

- Valid ring `CONNECT_IND` frame: `3794`
- Capture time: `40.372957s`
- Central / initiator address: redacted
- Ring / advertiser address: `41:42:2e:c7:5b:6a`
- Data channel access address after connection: `0xaf9abbab`

Pairing/encryption happened around `43.7s` to `47.7s`. The same main custom protocol handles were used:

```text
0x0017 = app -> ring writes
0x0019 = ring -> app notifications
0x001a = CCCD for notifications
```

#### Battery

The standard BLE Battery service was read:

```text
Frame 4407
Handle 0x002c Battery Level: 100%
```

The low-battery alert seen in the app did not appear to come from the standard Battery Level characteristic in this capture. It may be stale app state or a custom status field that is not decoded yet.

#### SpO2 Measurement

Likely start SpO2 command:

```text
Frame 4905 / 60.527s
Write 0x0017:
2301000000000000000000000000000000000000
```

Ring acknowledgement:

```text
Frame 4916 / 60.707s
Notify 0x0019:
2301000000000000000000000000000000000000
```

Repeated in-progress/status notification:

```text
2400000000000000000000000000000000000000
```

These repeated roughly once per second from about `61.27s` to `79.27s`.

Final SpO2 result:

```text
Frame 5699 / 80.327s
Notify 0x0019:
245e774d63050000000000000000000000000000
```

The app showed SpO2 around `99`. The result packet contains:

```text
0x63 = 99
```

Likely stop/end SpO2 command:

```text
Frame 5746 / 81.467s
Write 0x0017:
2300000000000000000000000000000000000000
```

Ring acknowledgement:

```text
2300000000000000000000000000000000000000
```

Current SpO2 interpretation:

```text
23 01 ...           start SpO2
24 00 ...           SpO2 measuring / progress
24 .. .. .. 63 05   SpO2 result, 0x63 = 99
23 00 ...           stop SpO2
```

#### Heart Rate In Pair6

Likely HR start command:

```text
Frame 6084 / 90.347s
Write 0x0017:
14b4000000000000000000000000000000000000
```

Ring acknowledgement:

```text
14b4000000000000000000000000000000000000
```

HR result notifications:

```text
Frame 6570:
140def146a530000000000000000000000000000

Frame 6685:
140fef146a540000000000000000000000000000

Frame 6725:
1410ef146a550000000000000000000000000000
```

The app showed around `85` BPM. These values match the same byte found in `ring-pair5`:

```text
0x53 = 83 bpm
0x54 = 84 bpm
0x55 = 85 bpm
```

Likely HR complete/status notification:

```text
Frame 6965 / 113.477s
Notify 0x0019:
2700000000000000000000000000000000000000
```

Likely HR stop/cleanup:

```text
Frame 7016 / 114.797s
Write 0x0017:
1500000000000000000000000000000000000000
```

Ring acknowledgement:

```text
1500000000000000000000000000000000000000
```

Current HR interpretation:

```text
14 b4 ...              start HR measurement
14 .. .. .. .. BPM ... HR update, BPM byte confirmed
27 00 ...              measurement complete/status, likely HR-related
15 00 ...              stop/close HR measurement
```

#### Selfie Mode

The selfie feature appears to use the custom app protocol rather than HID input notifications.

Enable selfie/clench mode:

```text
Frame 11675 / 238.638s
Write 0x0017:
0701000000000000000000000000000000000000
```

Ring acknowledgement:

```text
0701000000000000000000000000000000000000
```

Clench/shutter events from the ring:

```text
Frame 12204 / 252.858s
Notify 0x0019:
0602000000000000000000000000000000000000

Frame 12433 / 259.098s
Notify 0x0019:
0602000000000000000000000000000000000000

Frame 12526 / 261.498s
Notify 0x0019:
0602000000000000000000000000000000000000
```

Disable selfie/clench mode:

```text
Frame 12594 / 263.299s
Write 0x0017:
0700000000000000000000000000000000000000
```

Ring acknowledgement:

```text
0700000000000000000000000000000000000000
```

Current selfie interpretation:

```text
07 01 ... = enable selfie/clench detection
06 02 ... = ring clench / shutter event
07 00 ... = disable selfie/clench detection
```

#### Find Ring

Find-ring was later confirmed from the Python CLI run.

```text
Frame 7889 / 137.867s
Write:
040a000000000000000000000000000000000000

Notify:
040a000000000000000000000000000000000000
```

`04 0a` turns on the ring light. The `0x0a` byte may mean 10 seconds.

The Phase 2 CLI test also sent find-ring parameter variants:

```text
0401000000000000000000000000000000000000
0405000000000000000000000000000000000000
040a000000000000000000000000000000000000
0414000000000000000000000000000000000000
```

All were accepted and echoed by the ring. This strongly suggests byte `1` of command `0x04` is a parameter, probably find-ring light duration or intensity. Physical timing still needs to be recorded to prove the exact meaning.

The `0x52...` mode commands were tested from the Python CLI and did not visibly do anything:

```text
5200000000010000000000000000000000000000
5200000000020000000000000000000000000000
5200000000ffffffff0000000000000000000000
```

#### HID Notes

The ring exposes HID service `0x1812` and a HID report map. Report references were:

```text
0x003b = Report ID 1, Input Report
0x003f = Report ID 2, Input Report
0x0043 = Report ID 3, Input Report
0x0047 = Report ID 4, Input Report
```

The selfie action did not show clean HID input notifications in this capture. It appears to be delivered through custom notification `0602...`.

#### Pair6 Short Protocol Table

```text
0c 00 ...        device/status query
21 65 6e 2d ... locale string, "en-US"
23 01 ...        start SpO2
24 00 ...        SpO2 measuring / progress
24 .. .. .. 63   SpO2 result, 0x63 = 99
23 00 ...        stop SpO2
14 b4 ...        start HR
14 .. .. .. .. BPM  HR update, BPM byte confirmed
15 00 ...        stop/close HR
27 00 ...        measurement complete/status, probably HR-related
07 01 ...        enable selfie mode
06 02 ...        selfie clench/shutter event from ring
07 00 ...        disable selfie mode
04 0a ...        confirmed find-ring/light command
04 XX ...        find-ring/light with parameter byte, likely duration
52 ... 01 / 02   tested, no visible effect
52 ... ff        mode reset/cleanup candidate, no confirmed user feature
```

### Python CLI Live Test

Source log: `logs/smart-ring-20260526-011251.jsonl`

This test controlled the ring directly from macOS using Python/Bleak. Scanning, connecting, notification subscription, pairing, status query, SpO2, HR, selfie, find-ring, and locale command all worked.

The ring appeared in macOS as a CoreBluetooth UUID, not its real BLE MAC:

```text
SMART_RING
<macOS CoreBluetooth UUID>
```

The advertisement still exposed the expected manufacturer data:

```text
41422ec75b6a7a003a001600
```

#### Confirmed From CLI

Status query:

```text
Write:
0c00000000000000000000000000000000000000

Notify:
0c7a0041422ec75b6a3a001600c6b4538e15ea00
0c7a0041422ec75b6a3a00160031b5539a417aa9
```

SpO2 start:

```text
Write:
2301000000000000000000000000000000000000

Notify:
2301000000000000000000000000000000000000
```

SpO2 progress:

```text
2400000000000000000000000000000000000000
```

SpO2 final result from the live CLI run:

```text
24536c4261050000000000000000000000000000
```

Likely final-result structure:

```text
24 53 6c 42 61 05 ...
            ^^
            0x61 = 97 SpO2
```

This suggests byte index `4` in the final rich `0x24` packet is SpO2. Earlier `0x24` packets like `245300...`, `244f00...`, and `244e00...` appear to be intermediate values/status rather than final SpO2.

HR start:

```text
Write:
14b4000000000000000000000000000000000000

Notify:
14b4000000000000000000000000000000000000
```

HR values:

```text
1456f4146a520000000000000000000000000000  -> 0x52 = 82 bpm
1458f4146a510000000000000000000000000000  -> 0x51 = 81 bpm
145ff4146a520000000000000000000000000000  -> 0x52 = 82 bpm
```

HR complete/status:

```text
2700000000000000000000000000000000000000
```

Selfie mode:

```text
0701000000000000000000000000000000000000  enable
0602000000000000000000000000000000000000  clench/shutter event
0700000000000000000000000000000000000000  disable
```

Find-ring:

```text
040a000000000000000000000000000000000000
```

Locale:

```text
21656e2d55530000000000000000000000000000
```

#### Still Unknown

Setup/status notifications seen after status query:

```text
2062e80728090abebb0000000000000000000000
f60000007a001600000000000000000000000000
f641422ec75b6a00000000000000000000000000
03dff3146a000000000000000000000000000000
13dff3146a000000000000000000000000000000
0b64000000000000000000000000000000000000
2800000000000000000000000000000000000000
```

Updated after the later Phase 2 CLI test:

- `0x03` / `0x13` are now likely activity/motion/step-related packets.
- `0x0b` likely carries a percent-like value, possibly battery or status.
- `0x28` appears after SpO2 completion/stop and may be a measurement-finished/status marker.
- `0x20` and `0xf6` still look like setup/config/identity packets.

### Python CLI Phase 2 / Activity Test

Source log: `logs/smart-ring-20260526-014557.jsonl`

This run repeated the known commands, added a Phase 2 sequence for find-ring parameter variants, and left notifications enabled while the ring was moved by hand.

#### Services Reconfirmed

macOS/Bleak service discovery again showed:

```text
0000fef5-0000-1000-8000-00805f9b34fb  Dialog Semiconductor GmbH
000056ff-0000-1000-8000-00805f9b34fb  Vendor specific
0000ff12-0000-1000-8000-00805f9b34fb  Vendor specific
0000180f-0000-1000-8000-00805f9b34fb  Battery Service
0000180a-0000-1000-8000-00805f9b34fb  Device Information
```

#### Startup / Notify-On Burst

Immediately after enabling notifications, the ring sent:

```text
2062e80728090abebb0000000000000000000000
0c7a0041422ec75b6a3a001600bc2672ce009256
f60000007a001600000000000000000000000000
f641422ec75b6a00000000000000000000000000
03abfb146a000000000000000000000000000000
13abfb146a000000000000000000000000000000
0b63000000000000000000000000000000000000
```

Current interpretation:

```text
0x20 = likely device time/date/config packet
0x0c = status response with embedded ring address
0xf6 = identity/config chunks, one includes ring address
0x03 = activity/motion/step-like data packet
0x13 = companion/summary activity packet
0x0b = percent-like status; byte 1 was 0x63 = 99 in this run
```

#### Movement / Activity Packets

While notifications were enabled and the ring was moved, many `0x03` / `0x13` pairs arrived without sending a measurement command.

Example pair:

```text
03b3fb146a120000000f00000000000000000000
13b3fb146a120000000000000000000000000000
```

The first four bytes after the command ID appear to be a little-endian Unix timestamp:

```text
03 b3 fb 14 6a ...
   b3 fb 14 6a = 1779760051 = 2026-05-26 01:47:31 UTC
```

Observed changing fields in `0x03` packets:

```text
03 b3 fb 14 6a 12 00 00 00 0f 00 00 00 00 ...
03 c1 fb 14 6a 30 00 00 00 2a 00 00 00 02 ...
03 b6 fc 14 6a 54 00 00 00 49 00 00 00 04 ...
```

Current inferred structure:

```text
byte 0      command ID: 0x03
bytes 1-4   little-endian Unix timestamp
byte 5      activity counter, motion count, or step-like count
byte 9      second activity/count field
byte 13     coarse activity bucket / segment / calorie-like field
```

The `0x13` packets carry the same timestamp prefix and often a stable count value. They may be summaries or companion records for the same activity event.

This means activity/pedometer-style data is likely available from passive notifications. A controlled test with known step counts is needed to map the fields exactly.

#### Phase 2 Command Results

Automated Phase 2 sent:

```text
0401...   echoed
0405...   echoed
040a...   echoed
0414...   echoed
2301...   SpO2 start acknowledged
2300...   SpO2 stop acknowledged
14b4...   HR start acknowledged
1500...   HR stop acknowledged
```

Short Phase 2 measurement windows were intentionally conservative:

- 10 seconds of SpO2 produced progress packets but no final SpO2 result.
- 10 seconds of HR produced start/complete packets but no BPM value.

The earlier longer manual tests in the same run did produce valid results:

```text
SpO2 final:
2457704863050000000000000000000000000000
byte 4 = 0x63 = 99%

HR final:
145cfc146a560000000000000000000000000000
byte 5 = 0x56 = 86 bpm
```

#### Selfie Events

Selfie mode again worked:

```text
0701000000000000000000000000000000000000  enable
0602000000000000000000000000000000000000  clench/shutter event
0700000000000000000000000000000000000000  disable
```

Multiple `0602...` notifications were generated while moving/clenching the ring, confirming this is the phone-camera trigger event.

### Ring Pair7 Sync / Steps Findings

Source capture: `ring-pair7.pcapng`

This was a longer app session: pairing, app sync, HR/measurement activity, another sync, then the app was closed while the ring was used for walking. When the app was relaunched it showed:

```text
steps:    120 / 10000
calories: 6 / 395
mileage:  0.10 km / 7.5 km
sleep:    empty
```

The capture contains matching activity packets, which confirms the structure of `0x03`.

#### Activity Packet

After walking, the app showed `120` steps. The ring sent:

```text
037901156a780000006900000006000000000000
```

Decoded:

```text
03          command ID = activity packet
7901156a    timestamp, little-endian Unix time = 2026-05-26 02:12:09 UTC
78000000    steps = 120
69000000    distance-like field = 105
06000000    calories = 6
```

Current confirmed structure:

```text
byte 0       command ID: 0x03
bytes 1-4    little-endian Unix timestamp
bytes 5-8    steps, little-endian uint32
bytes 9-12   distance-like field, little-endian uint32
bytes 13-16  calories, little-endian uint32
```

The app mileage was `0.10 km` while the packet distance-like field was `105`. This is probably meters or meter-like units:

```text
105 units ~= 0.10 km
```

The earlier 90-step packet from the same capture was:

```text
030300156a5a0000004e00000004000000000000
```

Decoded:

```text
steps = 90
distance-like field = 78
calories = 4
```

#### Activity Summary Packet

The companion `0x13` packet after the 120-step reading was:

```text
137901156a550000003c00000078000000000000
```

Decoded fields:

```text
timestamp = 2026-05-26 02:12:09 UTC
field_a = 85
field_b = 60
steps = 120
```

`0x13` is therefore an activity summary or companion record. Its final u32 at bytes `13-16` also carries the step count.

#### Time Sync Command

The app sends command `0x01` with current Unix time and timezone offset:

```text
010a00156afc0000000000000000000000000000
```

Decoded:

```text
01          command ID = set/sync time
0a00156a    Unix timestamp = 2026-05-26 02:06:02 UTC
fc          signed timezone offset = -4 hours
```

Current structure:

```text
byte 0     command ID: 0x01
bytes 1-4  little-endian Unix timestamp
byte 5     signed timezone offset in hours
```

This matches US Eastern daylight time.

#### Activity Query Command

The app sent:

```text
0299b85a00000000000000000000000000000000
```

The ring acknowledged it and immediately sent `0x03` / `0x13` activity packets. This is likely the current activity query command.

#### Daily Goal / Config

The app sent:

```text
1a10270000000000000000000000000000000000
```

`10270000` little-endian is decimal `10000`, matching the app's daily step goal:

```text
steps goal = 10000
```

The calorie goal `395` and mileage goal `7.5 km` are visible in the app, but their packet locations are not confirmed yet. They may be in one of these config packets:

```text
190000173b011e02000000000000000000000000
1b01010000000900110000000050000000000000
44e5070101051e00000000000000000000000000
0aff031c00000000000000000000000000000000
```

Do not write arbitrary variants of these until their meaning is clearer.

#### App Sync Sequence

The official app sync sequence included:

```text
48...        app/client identifier
0c...        status query
01...        time sync
21...        locale
1d...        unknown, echoed
20...        device time/config query
02...        current activity query, triggers 0x03/0x13
19...        automatic HR schedule/config
1b...        unknown profile/config
1a...        goal/config, includes 10000 step goal
52...        air-control/HID mode candidate
44...        unknown profile/date/config
0a...        unknown config
10...        historical summary query
16...        historical measurement stream query
```

#### History / Measurement Sync

The app wrote:

```text
1000000000000000000000000000000000000000
```

The ring returned `0x10` summary records with timestamps:

```text
101cfb146a000042000000180000000000000000
10a0fe146a0000000000000000001e0000000000
107c30166a000000000000000000000000000000
```

The app also wrote:

```text
1600000000000000000000000000000000000000
```

In the app sync context this requests stored measurement history. The ring returned `0x16aa` and `0x16a0` chunks. The sample bytes include HR-like values such as `0x50`/80, `0x55`/85, `0x56`/86, and `0x54`/84.

This means `16 00...` is not only a generic stop/cleanup command; in the app sync flow it also pulls cached measurement chunks.

### Ring Pair8 Sleep Findings

Source capture: `ring-pair8.pcapng`

The app showed:

```text
steps:       328 / 10000
calories:    18 / 395
mileage:   0.28 km / 7.50 km
sleep:     5h 00m
deep:      0h 30m
light:     4h 30m
awake:     0h 00m
sleep time: 04:45 AM to 09:45 AM
```

#### Activity Confirmation

The current activity packet was:

```text
03fd7c156a480100001f01000012000000504600
```

Decoded:

```text
timestamp = 2026-05-26 10:59:09 UTC
steps = 328
distance-like field = 287 ~= 0.28 km
calories = 18
```

This confirms the `0x03` activity structure again.

#### Sleep Query

The app wrote:

```text
1000000000000000000000000000000000000000
```

The ring responded with `0x10` summary records and a series of `0x11` timeline records.

#### Sleep Timeline Packets

Example `0x11` packet:

```text
114c25156a282828282828282828282828282828
```

Structure:

```text
byte 0      command ID: 0x11
bytes 1-4   little-endian Unix timestamp for the block
bytes 5-19  fifteen 1-minute sleep stage samples
```

The `0x11` packets in this capture cover 20 blocks:

```text
20 packets * 15 minutes = 300 minutes = 5 hours
```

This matches the app's total sleep time.

Confirmed sleep stage sample values:

```text
0x28 = light sleep
0x63 = deep sleep
```

The capture had 18 light blocks and 2 deep blocks:

```text
18 * 15 minutes = 270 minutes = 4h30 light sleep
 2 * 15 minutes =  30 minutes = 0h30 deep sleep
```

This matches the app:

```text
Light sleep duration: 04:30
Deep sleep duration:  00:30
Awake duration:       00:00
```

Awake sample value is not known yet because this capture had no awake duration.

#### HR Schedule Note

After sync, the app's automatic HR schedule was configured for 30-minute cadence from 12:00 AM to 11:59 PM. The capture does not contain a clearly isolated setting write after that action.

One recurring config packet contains `0x1e = 30`:

```text
44e5070101051e00000000000000000000000000
```

This may be related to a 30-minute cadence, but it also appeared in earlier syncs. Treat it as unconfirmed until a focused settings-only capture is compared against a different cadence.

## Historical Measurement Streams

After the likely start command `1601...`, the ring emitted a sequence like:

```text
16f00091136a0a00000000000000000000000000
16aa01805b146a01000000000000000000000000
16a0805b146a000045454545454545454c454545
16aa02e85c146a01000000000000000000000000
16a0e85c146a00004b4b4b4b4b4b4b4b4b4b4b4b
...
```

Inferred structure:

```text
0x16 0x01 = start command
0x16 0x00 = stop command
0x16 0xaa / 0x16 0xa0 = measurement stream chunks
0x16 0xff = stream stopped / done acknowledgement
```

The stream chunk format is not fully decoded yet.

## Sniffing Notes

### Factory Reset Capture Plan

Factory reset probably wipes stored flash/history and pairing/app state. Capture it only after saving any app screenshots or CLI logs you care about.

Recommended sequence:

```text
1. Start nRF Sniffer before opening the JRING app.
2. Filter visually for the ring advertising address: 41:42:2e:c7:5b:6a.
3. Open JRING and connect to the ring.
4. Confirm Wireshark followed the connection and shows ATT traffic.
5. Let the normal startup/sync settle for 10-15 seconds.
6. Press factory reset in the app.
7. Do not stop capture immediately. Wait at least 60 seconds.
8. Watch whether the ring disconnects, advertises again, changes address, or requires pairing again.
9. Save the capture as ring-factory-reset1.pcapng.
10. Reopen the app and capture the first post-reset pairing/sync as ring-after-reset1.pcapng.
```

Things to look for:

```text
ATT Write Request to 0x33f3 near the button press
notification / ack on 0x33f4
LL_TERMINATE_IND or disconnect reason
new advertising data
whether stored activity/sleep packets disappear
whether 0x0c status/device response changes
whether 0xf6 identity/config chunks change
```

Do not try random reset-like commands from the CLI until the app reset command is captured. In our protocol, `0x1a` is already known to include the 10000 step goal, so Oura's `0x1a = factory reset` does not apply here.

### nRF Sniffer / Wireshark Capture Notes

Early pairing captures showed the ring advertising and sometimes even pairing attempts, but did not show useful app data after pairing. The capture became much more reliable after enabling the nRF Sniffer options:

```text
Find auxiliary pointer data
Find auxiliary scan response data
```

Even with those enabled, the sniffer can still miss the actual connection or lose useful ATT traffic sometimes. If the capture does not show writes to handle `0x0017` or notifications from handle `0x0019` after pairing, treat that run as incomplete and capture again.

The practical sign of a good capture is not just seeing `SMART_RING` advertisements. A useful protocol capture should show:

```text
CONNECT_IND
SMP pairing/encryption, if pairing happens
GATT discovery
CCCD write to handle 0x001a
ATT writes to handle 0x0017
ATT notifications from handle 0x0019
```

### Useful Wireshark Filters

Connection:

```text
btle.advertising_header.pdu_type == 0x05
```

Ring advertising:

```text
btle.advertising_address == 41:42:2e:c7:5b:6a
```

GATT/app protocol:

```text
btatt || btl2cap || btsmp
```

Main app protocol handles:

```text
btatt.handle == 0x0017 || btatt.handle == 0x0019 || btatt.handle == 0x001a
```
