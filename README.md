# Saab J2534 Nano Probe

A small, **read-only** J2534 diagnostic probe for the Saab 9-3 NG (2003–2012),
written to answer one question: *does a given J2534 adapter actually do what a
Tech2 emulator (Tech3Win / Tech2Win) needs on the single-wire CAN I-bus (pin 1)?*

It was built to debug why Tech3Win reported **"I-Bus Missing. Tech 2 cannot
contact CIM via DLC pin 1"** with a VXDIAG VCX Nano, and to separate an adapter
problem from an emulator problem.

> Scope: this tool only looks at the **transport / capability** layer (opening
> channels, listening, and a plain VIN read). It has nothing to do with security
> access, seed/key, or module Add/Remove, and contains none of that.

## What it checks

Run it against your installed J2534 driver and it reports, step by step:

1. **Registry** – which J2534 (04.04) interfaces are installed and whether each
   advertises `SW_CAN_PS` (single-wire CAN). Works even without the adapter
   plugged in.
2. **Open + version** – opens the driver, prints firmware / DLL / API and the
   battery voltage the adapter sees.
3. **SW-CAN (I-bus)** – opens a `SW_CAN_PS` channel on pin 1 at 33 333 bit/s and
   listens for live I-bus traffic.
4. Optional extra modes (see below).

Everything printed is also written to a line-buffered `probe_YYYY-MM-DD_HHMMSS.log`
next to the script, so you can just attach that file instead of copy/pasting.

## Modes

```
probe.bat                 registry + open + listen on the I-bus (default)
probe.bat --hs            also test HS-CAN (P-bus, 500k)
probe.bat --seconds 15    listen longer
probe.bat --dual          does the adapter hold SW-CAN and HS-CAN open at once?
probe.bat --roffe         3-step test: send 241 02 1A 90 to the CIM, expect 641
probe.bat --roffe2        follow-up: config 3 + each of 4 emulator quirks, one by one
probe.bat --active [--hv-wake]   send GMLAN wake + TesterPresent, then listen
probe.bat --dll "C:\path\to\other_j2534.dll"   use a specific adapter
```

The `--roffe` mode sends a **VIN read** (`1A 90`) to the CIM on 0x241 and watches
for the module's reply on 0x641, in three channel/flag/filter configurations.
It is the most useful mode for proving whether the *adapter* can do the request/
response the emulator needs. (VIN read only — no security access, no writes.)

The `--roffe2` mode takes the passing config 3 and re-runs it with each of four
things the emulator does differently added one at a time — SW-CAN opened before
HS-CAN, a high-voltage wake first, a third (MS-CAN) channel with TesterPresent on
all three buses, and the `241 01 20` request (expecting `641 01 60`) — then all
four together. It isolates which single behaviour, if any, stops the CIM
answering. Still read-only on modules: only a read/ReturnToNormalMode request and
TesterPresent, no security access, no writes.

## Requirements

- Windows with a J2534 driver installed for your adapter (e.g. VX Manager for a
  VXDIAG VCX Nano).
- **32-bit Python 3** — J2534 driver DLLs are 32-bit, so 64-bit Python cannot
  load them. The probe detects this and tells you.
- Ignition on (and engine running for a busy P-bus) when testing on a car.
- Keep a battery charger connected, as with any on-car work.

## What it found (VCX Nano, Nov 2026)

Against a VXDIAG VCX Nano on a Saab 9-3 NG, all three steps of the `--roffe`
test returned a valid CIM response on 0x641 (the VIN), including with HS-CAN open
at the same time and with the emulator's exact connect flags and filters. So the
adapter transmits on pin 1 and holds **two** buses open at once.

The `--roffe2` run then isolated the actual cause of "I-Bus Missing": re-running
that passing config with each emulator quirk added one at a time, the CIM's 0x641
kept coming **until a third channel (MS-CAN, `CAN_PS` at 95238, `J1962_PINS`
0x030B) was opened** — at which point single-wire reception went silent (0
frames). The MS-CAN channel opens without error, but once it is open this adapter
stops receiving on SW-CAN. A silent "can't hold three buses open at once" limit.

Resolution: with the emulator's **"Disable MS-CAN"** option enabled (so only
SW-CAN + HS-CAN are open), the VCX Nano works end to end on the 9-3 NG — read,
security access, and a full module Add/Remove on a real car. No Saab module lives
on MS-CAN, so nothing is lost by disabling it.

(For comparison: a ChipSoft J2534 Mid/Pro states in its own driver dialog that it
*cannot* use SW-CAN on pin 1 and CAN on pins 3–11 at the same time either.)

## Safety

Read-only by default. The only frames it ever transmits are, in `--roffe` /
`--active`, a GMLAN wake, TesterPresent, and a VIN **read** request. It never
writes to a module, never touches security access, and never does Add/Remove.

## License

MIT — see [LICENSE](LICENSE).

Built together with Claude for a Saab 9-3 NG diagnostics project. Credits to the
Saab community tools it takes cues from (oamne's `saab-j2534-sniffer`, the
OpenSAAB project, and roffe's Tech3Win) for the SW-CAN parameters.
