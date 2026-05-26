# SMART_RING Lab Notes

Brief working notes for the BLE reverse engineering runs.

## Files

- `ring-measure.pcapng`
- `ring-pairing.pcapng`
- `ring-pair2.pcapng`
- `ring-pair3.pcapng`
- `ring-pair5.pcapng`
- `ring-pair6.pcapng`
- `ring-pair7.pcapng`
- `ring-pair8.pcapng`
- `logs/smart-ring-20260526-011251.log`
- `logs/smart-ring-20260526-011251.jsonl`
- `logs/smart-ring-20260526-014557.log`
- `logs/smart-ring-20260526-014557.jsonl`
- `smart_ring_cli.py`
- `ring-protocol-notes.md`

## Product Listing

User-provided order listing: `https://www.aliexpress.us/item/3256810466598469.html`

Note: AliExpress sellers often change or reuse listings. The ring under test does not appear to have an OLED/display, so display-ring listings such as some SR08/TK9 pages are only nearby context.

Listed hardware:

- Main chip: Coolchip AB2026
- Memory: `64KB + 8K cache + 8Mbit flash`
- Bluetooth: `5.4`
- Material: `304 stainless steel`
- Charging: magnetic, about 2 hours
- Runtime: 3-5 days normal use

Learning: earlier DA14585 notes came from similar JRING/SR08/TK9 listings, not this exact order page. AB2026 is the current seller-listed chip, but the BLE protocol findings are more reliable than the listing hardware text.

## ring-measure.pcapng

First sniffing attempt while trying measurement behavior.

Result: mostly advertising traffic. No useful followed connection/protocol data.

Learning: nRF sniffer must follow the actual connection. Advertising alone is not enough to decode app commands.

## ring-pairing.pcapng

Pairing capture attempt.

Result: mostly advertising again. No useful app protocol.

Learning: need to catch the `CONNECT_IND` for the ring and stay on that connection.

## ring-pair2.pcapng

Pairing after waiting 20-30 seconds. iPhone scan showed `SMART_RING 41:42:2E:C7:5B:6A -64`, then HR measurement was triggered.

Result: identified the target ring advertisement and address, but did not capture a useful followed connection.

Learning: confirmed advertised name and address. Still needed better connection capture.

## ring-pair3.pcapng

Connected/disconnected twice with only this ring MAC.

Result: saw `SMART_RING` scan response and target address, but still no useful app traffic.

Learning: address filtering helped identify the ring, but nRF/Wireshark still missed or did not follow the useful connection.

## ring-pair5.pcapng

First good capture with a valid connection.

Result: captured pairing/encryption, GATT discovery, app writes, and notifications.

Learning:

- Ring address: `41:42:2e:c7:5b:6a`
- App service: `0x56ff`
- Write characteristic: `0x33f3`, handle `0x0017`
- Notify characteristic: `0x33f4`, handle `0x0019`
- Notifications enabled through handle `0x001a`
- HR values confirmed from app: `0x50 = 80`, `0x51 = 81` in `0x14...` notifications.

## ring-pair6.pcapng

Good full workflow capture. Paired, started SpO2, started HR, used find-ring, used selfie, left ring connected for a while.

Result: decoded several feature flows.

Learning:

- SpO2 start: `2301...`
- SpO2 progress: `2400...`
- SpO2 stop: `2300...`
- HR start: `14b4...`
- HR result: `0x14...`, BPM at byte index `5`
- Selfie enable: `0701...`
- Selfie event: `0602...`
- Selfie disable: `0700...`
- Find-ring candidate: `040a...`
- `0x52...` looked like a mode command but was not proven.

## ring-pair7.pcapng

Long app sync capture. Paired, hit sync, triggered measurement behavior, synced again, closed app, walked, sat, reopened app, saw `120` steps, then synced again.

Result: decoded current activity data and app sync setup.

Learning:

- App showed `120 / 10000` steps, `6 / 395` calories, and `0.10 km / 7.5 km` mileage.
- Matching activity packet: `037901156a780000006900000006000000000000`.
- `0x03` bytes `1-4` are Unix timestamp.
- `0x03` bytes `5-8` are steps: `0x78 = 120`.
- `0x03` bytes `9-12` are distance-like units: `105`, matching about `0.10 km`.
- `0x03` bytes `13-16` are calories: `6`.
- Companion `0x13` packet also carries steps at bytes `13-16`.
- Time sync command found: `01 [unix time] [timezone offset] ...`.
- Current activity query candidate: `0299b85a...`, followed by `0x03` / `0x13`.
- `1a102700...` contains `10000`, matching the daily step goal.
- `10...` returns historical summary records.
- `1600...` in sync context pulls stored measurement chunks, not just stop/cleanup.

## ring-pair8.pcapng

Morning app sync capture with sleep data visible in the app. App showed `328` steps, `18` calories, `0.28 km`, `5h00m` sleep, `0h30m` deep sleep, `4h30m` light sleep, and `0h00m` awake. After sync, HR measurement was triggered, but clean live HR packets were not visible in this capture.

Result: decoded sleep timeline packets.

Learning:

- Activity packet `03fd7c156a480100001f01000012000000504600` decodes to `328` steps, `287` distance-like units, `18` calories.
- Sleep/history query uses `100000...`.
- Sleep timeline packets use command `0x11`.
- `0x11` bytes `1-4` are timestamp.
- `0x11` bytes `5-19` are fifteen 1-minute sleep stage samples.
- `0x28` means light sleep.
- `0x63` means deep sleep.
- 20 timeline packets * 15 minutes = 5 hours, matching the app.
- 18 light blocks = 4h30 light sleep.
- 2 deep blocks = 0h30 deep sleep.
- Awake sample value is still unknown because the app showed `0h00m` awake.
- Automatic HR schedule setting was not clearly isolated; `44...1e...` contains `30` but is not confirmed as cadence.

## ring-pair9.pcapng

Long settings/reset capture. User synced, checked firmware/version screen, enabled air control, turned automatic HR test off and on again, then pressed factory reset twice.

Result: captured a good pre-reset connection, a factory-reset command, and a post-reset reconnect.

Learning:

- Capture had two useful connections:
  - First `CONNECT_IND` at about `37.24s`.
  - Second `CONNECT_IND` at about `133.69s`, after factory reset.
- Firmware/version screen mostly caused standard Device Information and HID reads:
  - PnP ID read from handle `0x0030`: vendor source Bluetooth SIG, vendor `0x05ac`, product `0x0220`, version `0x0110`.
  - HID Information read: `bcdHID 0x0111`.
  - HID Report Map read from handle `0x0037`.
- HID Report Map includes media and pointer controls:
  - next/previous track, volume up/down, mute, play/pause.
  - touch pad, mouse/pointer, wheel, X/Y, buttons.
- Air control likely uses BLE HID plus `0x52` custom mode writes:
  - `520000000001...`
  - `520000000002...`
  - `5200000000ffffffff...`
- A new `0x1b` config variant also appeared and may be related to air control:
  - Usual sync value: `1b01010000000900110000000050000000000000`
  - New value: `1b01010000000900110000010050000000000000`
- Automatic HR schedule command is now much clearer:
  - Off: `190000173b001e02000000000000000000000000`
  - On: `190000173b011e02000000000000000000000000`
  - Likely fields: start `00:00`, end `23:59`, enable byte `0/1`, cadence `0x1e = 30 minutes`, mode/type `0x02`.
- Factory reset command:
  - `0efedcba98765432100000000000000000000000`
  - Magic payload is `fe dc ba 98 76 54 32 10`.
  - No app-protocol ack was captured before disconnect/reconnect.
- After reset, activity packets returned zeroed values:
  - `032d90156a000000000000000000000000000000`
  - `132d90156a000000000000000000000000000000`
- Reset did not change the BLE address or GATT layout.
- Pressing factory reset twice only produced one visible `0x0e...` write in the capture; the second tap likely happened after disconnect, was ignored, or was outside useful captured app traffic.

## smart-ring-20260526-011251 CLI Run

Used `smart_ring_cli.py` from macOS with Python/Bleak.

Result: direct control worked. Scanning, connecting, notification subscription, pairing, status query, SpO2, HR, selfie, find-ring, and locale command all worked.

Learning:

- MacBook BLE is enough for app development. nRF dongle is only needed for sniffing.
- macOS shows a CoreBluetooth UUID instead of the real BLE MAC.
- Confirmed UUIDs:
  - Service: `000056ff-0000-1000-8000-00805f9b34fb`
  - Write: `000033f3-0000-1000-8000-00805f9b34fb`
  - Notify: `000033f4-0000-1000-8000-00805f9b34fb`
- Confirmed find-ring command: `040a...`
- `mode 1` / `mode 2` using `52...01` and `52...02` did not visibly do anything.
- Final SpO2 rich packet looked like `24536c426105...`; likely SpO2 byte is index `4` (`0x61 = 97`).

## smart-ring-20260526-014557 CLI Run

Second live CLI run. Repeated known commands, enabled notifications while moving the ring by hand, ran SpO2/HR/selfie, then ran automated `phase2`.

Result: found likely activity/motion packets and confirmed Phase 2 command behavior.

Learning:

- After `notify on`, the ring sent setup/status packets: `0x20`, `0x0c`, `0xf6`, `0x03`, `0x13`, `0x0b`.
- Moving the ring produced many `0x03` / `0x13` packet pairs without starting HR or SpO2.
- `0x03` packets contain a little-endian Unix timestamp in bytes `1-4`.
- Changing fields in `0x03` packets look like activity/step/motion counters.
- `0x13` appears to be a companion or summary packet for activity data.
- `0x0b63...` may be a percent-like status value; possibly battery/status.
- Manual SpO2 final packet: `245770486305...`, byte `4` = `0x63` = `99%`.
- Manual HR final packet: `145cfc146a56...`, byte `5` = `0x56` = `86 bpm`.
- Selfie events again appeared as repeated `0602...` packets.
- Phase 2 find variants `0401...`, `0405...`, `040a...`, `0414...` were all echoed, suggesting byte `1` is a find-ring parameter.
- Short 10s Phase 2 SpO2/HR windows were too short for final values but did confirm start/stop acknowledgements.

## smart-ring-20260526-124826 CLI Run

Controlled CLI run after learning factory reset, automatic HR schedule, and air-control candidates.

Result: pre-reset direct control worked; after factory reset and manual macOS Bluetooth removal/reconnect, writes still completed but no notifications came back and HR/SpO2 did not visibly start.

Learning:

- Before reset, CLI connection and notifications were healthy.
- Activity query returned `36` steps / `31` distance units / `1` calorie, then later `60` steps / `52` distance units / `3` calories.
- `0x19` automatic HR schedule writes were accepted/echoed:
  - `190000173b001e02000000000000000000000000` off.
  - `190000173b011e02000000000000000000000000` on, 30 min.
  - `190000173b010a02000000000000000000000000` accepted as likely 10 min cadence.
- `0x52...01` did not echo, but right after it the ring emitted rapid `0x03`/`0x13` activity packets while the ring was being moved.
- `0x1b01010000000900110000010050000000000000` and the usual `...0000...` variant were accepted/echoed.
- CLI factory reset write succeeded: `0efedcba98765432100000000000000000000000`.
- After reset, the ring still advertised as `SMART_RING` with the same manufacturer data and same macOS CoreBluetooth UUID.
- The post-reset connection succeeded, and writes to `0x33f3` completed, but there were no `0x33f4` notifications.
- Root cause in this test was at least partly CLI state: the ring disconnected under the CLI after reset, but the CLI still thought notifications were enabled, so `notify on` was skipped after reconnect.
- CLI was patched to clear notification state on disconnect/reconnect and tolerate stale `stop_notify` failures.
- Next post-reset test should be: `scan`, `connect`, `notify on`, confirm startup notifications, `status`, `time sync`, `locale`, `activity`, then HR/SpO2.

## smart-ring-20260526-125805 CLI Run

Attempted to interact with a ring that was already connected/paired at the macOS level.

Result: the CLI did not connect to the ring. Both scans failed to find `SMART_RING`; then `notify on` tried to auto-connect, scanned again, still found no target, and failed with `No selected device`.

Learning:

- A macOS Bluetooth pairing/bond is not the same as an active Bleak client connection inside the CLI.
- If the ring is already connected to another central, such as the JRING app or macOS HID, it may not advertise as `SMART_RING`, so a normal CLI scan cannot select it.
- To connect without scanning, pass the cached CoreBluetooth UUID from a previous successful scan/connect:
  - `python3 smart_ring_cli.py --address 2125B1FC-3067-2D98-889E-F89D13C4BEFC`
- The CLI scan matcher was updated to select the ring by either name `SMART_RING` or manufacturer data prefix `41422ec75b6a`.

## smart-ring-20260526-133926 CLI Run

Focused CLI run for HID/air-control exploration.

Result: custom ring protocol worked, but HID was not exposed to the Python/Bleak client on macOS.

Learning:

- Ring scanned and connected normally.
- `0x33f4` notifications worked.
- Startup/status/time/locale traffic worked:
  - `20...`
  - `0c...`
  - `f6...`
  - `03...`
  - `13...`
  - `0b63...`
  - time sync ack `01...`
  - locale ack `21...`
- `hid scan` found no HID service/characteristics through Bleak.
- `hid map` failed because characteristic `0x2a4b` was not present in Bleak's discovered services.
- `hid on` found no HID notify candidates.
- This does not contradict the Wireshark capture that showed HID. It likely means macOS/CoreBluetooth is hiding or owning BLE HID services, especially if the ring is treated as a system HID/media device.
- `520000000001...`, `520000000002...`, and `5200000000ffffffff...` writes completed, but did not echo.
- After `52...01`, movement produced normal activity packets, rising from `0` to `41` steps and `2` calories. This may simply be step counting from movement, not proof that `0x52` controls air mode.
- Next HID work should use Wireshark while the phone/JRING app enables air control, or a BLE stack/API that can access HID reports directly.

## External Colmi R02 Research

Reviewed `tahnok/colmi_r02_client` and `colmi.puxtril.com`.

Result: similar product category, but different BLE protocol.

Learning:

- Colmi R02 uses Nordic-UART-like service `6e40fff0...`.
- Colmi packets are 16 bytes with checksum.
- Our ring uses `0x56ff` service and 20-byte packets.
- Colmi commands are useful as a feature roadmap, not directly usable command bytes.

## Current Confirmed Feature Set

- Scan by name/manufacturer data.
- Connect from macOS with Bleak.
- Subscribe to notifications.
- Status query.
- Time sync.
- Standard BLE battery read.
- Current steps/activity query.
- Step, calorie, and distance-like activity decode.
- Sleep timeline query and light/deep sleep decode.
- Live HR measurement.
- Live SpO2 measurement.
- Find-ring light.
- Selfie/clench event.
- Locale command acknowledgement.

## Next Lab Targets

- Test the new CLI `activity`, `time sync`, `sync baseline`, `sleep`, and `history` commands.
- Do controlled movement tests with known counts: still, 10 steps, 20 steps, shake-only, clench-only.
- Record physical find-ring light timing for `0401`, `0405`, `040a`, and `0414`.
- Locate calorie goal `395` and mileage goal `7.5 km` in config packets.
- Discover historical HR, historical SpO2, awake sleep sample value, and remaining schedule/config commands.
- Do a focused air-control test while playing music/video and sniff HID report notifications.
- Decode unknown setup/status packets: `0x20`, `0xf6`, `0x03`, `0x13`, `0x0b`, `0x28`.
