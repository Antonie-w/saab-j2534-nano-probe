#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (versie 15-11-2026: --sniff toegevoegd; 14-11: --roffe2)
"""
J2534 Nano Probe  -  VCX Nano / Tech3Win haalbaarheidstest
===========================================================

Doel: VOORDAT je Tech3Win op de VCX Nano richt (of iets op een echte auto
probeert), zeker weten dat de J2534-driver van de Nano doet wat Tech3Win
vraagt: een single-wire CAN-kanaal (SW_CAN_PS) op OBD-pin 1, 33.333 bit/s
(de I-bus van de 9-3 NG), plus de gewone HS-CAN.

Deze probe is READ-ONLY in de standaardstand:
  - hij leest de Windows-registry (welke J2534-driver(s) staan geregistreerd),
  - opent de driver en vraagt de versie op,
  - probeert een SW_CAN_PS- en een HS-CAN-kanaal te OPENEN,
  - en LUISTERT passief mee (stuurt zelf GEEN enkel frame naar de auto).

Pas met de losse vlag  --active  stuurt hij iets (alleen een GMLAN
TesterPresent / wake, zoals oamne's agent; nog steeds GEEN security access,
GEEN Add/Remove, GEEN schrijfacties naar modules). Standaard staat dat UIT.

Niets in dit programma raakt het seed/key- of 0x27-beveiligingsalgoritme.

BELANGRIJK:
  * Draai dit met 32-bit Python. J2534-driver-DLL's zijn 32-bit; 64-bit Python
    kan ze niet laden. De probe controleert dit en stopt met een duidelijke
    melding als je per ongeluk 64-bit draait.
  * Voor zinvol passief verkeer op de I-bus: contact aan (stand II / ON).
  * Houd een acculader aangesloten, net als bij al je andere auto-werk.

Gebaseerd op de bevestigde J2534-instellingen uit jouw eigen LED Enabler
(SW_CAN_PS = 0x8008, J1962_PINS = 0x0100 voor pin 1, 33.333 bit/s) en op
oamne's saab-j2534-sniffer. Waar een constante niet 100% zeker is, staat dat
in een commentaar; de probe print bij ELKE stap de ruwe retourcode en de
driver-fouttekst, zodat we bij een afwijking precies kunnen zien wat er speelt.
"""

import sys
import os
import time
import argparse
import struct
import ctypes
from ctypes import (
    Structure, POINTER, byref, create_string_buffer,
    c_ulong, c_long, c_ubyte, c_char_p, c_void_p,
)

# --------------------------------------------------------------------------
# J2534 constanten
# --------------------------------------------------------------------------

# Protocol-ID's
PROTO_CAN          = 5           # gewone CAN (raw), b.v. HS-CAN 500k
PROTO_ISO15765     = 6           # ISO-TP over CAN (HS-CAN diagnose)
PROTO_SW_CAN_PS    = 0x8008      # J2534-2 single-wire CAN, pin-geselecteerd
                                 #   (bevestigd uit de LED Enabler)
PROTO_CAN_PS       = 0x8004      # J2534-2 pin-switchable CAN (MS-CAN, pins 3/11)
                                 #   (vermoedelijke id; probe meldt het als 't faalt)

# Connect-flags
CAN_29BIT_ID       = 0x00000100  # 29-bit ID's (NIET gebruikt: GMLAN = 11-bit)
CAN_ID_BOTH        = 0x00000800  # accepteer 11- EN 29-bit (roffe's test 3)

# TxFlags
TX_SW_CAN_HV_TX    = 0x00000400  # single-wire high-voltage wake (alleen --active)

# Ioctl-ID's
GET_CONFIG         = 0x01
SET_CONFIG         = 0x02
READ_VBATT         = 0x03

# SCONFIG-parameter-ID's
DATA_RATE          = 0x01
LOOPBACK           = 0x03        # 0 = geen loopback (roffe's test 3)
J1962_PINS         = 0x8001      # J2534-2: welke OBD-pin voor single-wire
PIN_1              = 0x0100      # waarde voor pin 1 (bevestigd uit LED Enabler)

# Filtertypes
PASS_FILTER        = 1

# Bekende 9-3 NG module-ID's (alleen om de log leesbaarder te maken)
KNOWN_IDS = {
    0x241: "CIM", 0x242: "BCM", 0x243: "DDM", 0x245: "ACC/CIM",
    0x246: "IPC", 0x248: "PDM", 0x249: "REC", 0x24A: "RLDM",
    0x24B: "RRDM", 0x24F: "UEC", 0x253: "SDAR", 0x257: "ACM",
    0x258: "EHU", 0x259: "UHP", 0x25D: "ONSTAR",
    0x100: "SWCAN wake", 0x101: "SWCAN functional",
    0x130: "cyclisch", 0x135: "cyclisch",
    0x7E0: "ECM (T8)", 0x7E8: "ECM resp", 0x7E1: "TCM",
    0x641: "CIM resp", 0x64F: "UEC resp", 0x649: "REC resp",
}


# --------------------------------------------------------------------------
# J2534 structs
# --------------------------------------------------------------------------

class PASSTHRU_MSG(Structure):
    _fields_ = [
        ("ProtocolID",     c_ulong),
        ("RxStatus",       c_ulong),
        ("TxFlags",        c_ulong),
        ("Timestamp",      c_ulong),
        ("DataSize",       c_ulong),
        ("ExtraDataIndex", c_ulong),
        ("Data",           c_ubyte * 4128),
    ]


class SCONFIG(Structure):
    _fields_ = [("Parameter", c_ulong), ("Value", c_ulong)]


class SCONFIG_LIST(Structure):
    _fields_ = [("NumOfParams", c_ulong), ("ConfigPtr", POINTER(SCONFIG))]


# --------------------------------------------------------------------------
# Hulpfuncties
# --------------------------------------------------------------------------

def hr(title=""):
    print("-" * 70)
    if title:
        print(title)
        print("-" * 70)


def make_can_msg(proto, can_id, payload=b"", txflags=0):
    """Bouw een PASSTHRU_MSG met 11-bit CAN-ID in de eerste 4 bytes (big-endian)."""
    m = PASSTHRU_MSG()
    m.ProtocolID = proto
    m.TxFlags = txflags
    data = struct.pack(">I", can_id) + payload
    m.DataSize = len(data)
    for i, b in enumerate(data):
        m.Data[i] = b
    return m


def id_label(can_id):
    name = KNOWN_IDS.get(can_id)
    return f"0x{can_id:03X} ({name})" if name else f"0x{can_id:03X}"


# --------------------------------------------------------------------------
# Registry: welke J2534-drivers staan geregistreerd (werkt zonder hardware)
# --------------------------------------------------------------------------

def read_registry():
    """Lees alle geregistreerde J2534 04.04-interfaces + hun capability-vlaggen."""
    try:
        import winreg
    except ImportError:
        print("  (winreg niet beschikbaar - draai je dit wel op Windows?)")
        return []

    found = []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\PassThruSupport.04.04"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\PassThruSupport.04.04"),
    ]
    seen_dlls = set()
    for hive, path in roots:
        try:
            base = winreg.OpenKey(hive, path)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(base, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(base, sub)
            except OSError:
                continue
            info = {"regkey": sub, "Name": "", "FunctionLibrary": "", "caps": {}}
            j = 0
            while True:
                try:
                    vname, vdata, _ = winreg.EnumValue(k, j)
                except OSError:
                    break
                j += 1
                if vname == "Name":
                    info["Name"] = str(vdata)
                elif vname == "FunctionLibrary":
                    info["FunctionLibrary"] = str(vdata)
                else:
                    # capability-vlaggen (CAN, ISO15765, SW_CAN_PS, ...) zijn DWORD 1
                    info["caps"][vname] = vdata
            winreg.CloseKey(k)
            # dedup op DLL-pad (dezelfde interface staat vaak in beide registry-takken)
            dll_key = (info["FunctionLibrary"] or info["regkey"]).lower()
            if dll_key in seen_dlls:
                continue
            seen_dlls.add(dll_key)
            found.append(info)
        winreg.CloseKey(base)
    return found


# --------------------------------------------------------------------------
# J2534 DLL-wrapper
# --------------------------------------------------------------------------

class J2534:
    def __init__(self, dll_path):
        self.dll_path = dll_path
        self.dll = ctypes.WinDLL(dll_path)
        self.device_id = c_ulong(0)

        def bind(name, argtypes):
            fn = getattr(self.dll, name)
            fn.restype = c_long
            fn.argtypes = argtypes
            return fn

        self.PassThruOpen = bind("PassThruOpen", [c_void_p, POINTER(c_ulong)])
        self.PassThruClose = bind("PassThruClose", [c_ulong])
        self.PassThruConnect = bind(
            "PassThruConnect",
            [c_ulong, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)],
        )
        self.PassThruDisconnect = bind("PassThruDisconnect", [c_ulong])
        self.PassThruReadMsgs = bind(
            "PassThruReadMsgs",
            [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong],
        )
        self.PassThruWriteMsgs = bind(
            "PassThruWriteMsgs",
            [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong],
        )
        self.PassThruStartMsgFilter = bind(
            "PassThruStartMsgFilter",
            [c_ulong, c_ulong, POINTER(PASSTHRU_MSG), POINTER(PASSTHRU_MSG),
             POINTER(PASSTHRU_MSG), POINTER(c_ulong)],
        )
        self.PassThruIoctl = bind(
            "PassThruIoctl", [c_ulong, c_ulong, c_void_p, c_void_p]
        )
        self.PassThruReadVersion = bind(
            "PassThruReadVersion", [c_ulong, c_char_p, c_char_p, c_char_p]
        )
        self.PassThruGetLastError = bind("PassThruGetLastError", [c_char_p])

    def last_error(self):
        buf = create_string_buffer(128)
        try:
            self.PassThruGetLastError(buf)
            return buf.value.decode(errors="replace")
        except Exception:
            return "(geen fouttekst)"

    def check(self, rc, what):
        if rc == 0:
            print(f"  [OK]   {what}")
            return True
        print(f"  [FOUT] {what}  -> retourcode {rc}  :: {self.last_error()}")
        return False

    def open(self):
        return self.check(self.PassThruOpen(None, byref(self.device_id)),
                          f"PassThruOpen (device-id {self.device_id.value})")

    def version(self):
        fw = create_string_buffer(128)
        dll = create_string_buffer(128)
        api = create_string_buffer(128)
        rc = self.PassThruReadVersion(self.device_id, fw, dll, api)
        if rc == 0:
            print(f"  firmware : {fw.value.decode(errors='replace')}")
            print(f"  dll      : {dll.value.decode(errors='replace')}")
            print(f"  api      : {api.value.decode(errors='replace')}")
        else:
            print(f"  [FOUT] PassThruReadVersion -> {rc} :: {self.last_error()}")

    def vbatt(self):
        v = c_ulong(0)
        rc = self.PassThruIoctl(self.device_id, READ_VBATT, None, byref(v))
        if rc == 0:
            print(f"  accuspanning via adapter: {v.value/1000.0:.2f} V")
        else:
            print(f"  (accuspanning niet op te vragen: {self.last_error()})")

    def connect(self, proto, baud, flags=0):
        ch = c_ulong(0)
        rc = self.PassThruConnect(self.device_id, proto, flags, baud, byref(ch))
        ok = self.check(rc, f"PassThruConnect proto=0x{proto:X} baud={baud}")
        return ch if ok else None

    def set_pin1(self, ch):
        cfg = (SCONFIG * 1)()
        cfg[0].Parameter = J1962_PINS
        cfg[0].Value = PIN_1
        lst = SCONFIG_LIST(1, ctypes.cast(cfg, POINTER(SCONFIG)))
        rc = self.PassThruIoctl(ch, SET_CONFIG, byref(lst), None)
        self.check(rc, f"SET_CONFIG J1962_PINS=0x{PIN_1:04X} (single-wire op pin 1)")

    def pass_all_filter(self, ch, proto):
        mask = make_can_msg(proto, 0x000)
        patt = make_can_msg(proto, 0x000)
        fid = c_ulong(0)
        rc = self.PassThruStartMsgFilter(ch, PASS_FILTER, byref(mask),
                                         byref(patt), None, byref(fid))
        self.check(rc, "PASS-ALL filter (alles doorlaten, luisteren)")

    def pass_filter(self, ch, proto, mask_id, pat_id):
        mask = make_can_msg(proto, mask_id)
        patt = make_can_msg(proto, pat_id)
        fid = c_ulong(0)
        rc = self.PassThruStartMsgFilter(ch, PASS_FILTER, byref(mask),
                                         byref(patt), None, byref(fid))
        self.check(rc, f"PASS filter mask={mask_id:03X} pattern={pat_id:03X}")

    def set_config(self, ch, param, value, label=""):
        cfg = (SCONFIG * 1)()
        cfg[0].Parameter = param
        cfg[0].Value = value
        lst = SCONFIG_LIST(1, ctypes.cast(cfg, POINTER(SCONFIG)))
        rc = self.PassThruIoctl(ch, SET_CONFIG, byref(lst), None)
        self.check(rc, label or f"SET_CONFIG param=0x{param:X} value=0x{value:X}")

    def listen(self, ch, seconds):
        print(f"  luisteren {seconds} s ...")
        counts = {}
        n_total = 0
        end = time.time() + seconds
        BATCH = 32
        while time.time() < end:
            arr = (PASSTHRU_MSG * BATCH)()
            num = c_ulong(BATCH)
            rc = self.PassThruReadMsgs(ch, arr, byref(num), 200)
            # rc 0 = msgs ontvangen; andere codes (b.v. timeout) negeren we stil
            for i in range(num.value):
                m = arr[i]
                if m.DataSize >= 4:
                    can_id = struct.unpack(">I", bytes(m.Data[0:4]))[0] & 0x1FFFFFFF
                    counts[can_id] = counts.get(can_id, 0) + 1
                    n_total += 1
        return n_total, counts

    def send(self, ch, msg):
        num = c_ulong(1)
        rc = self.PassThruWriteMsgs(ch, byref(msg), byref(num), 200)
        return rc == 0

    def disconnect(self, ch):
        if ch is not None:
            self.PassThruDisconnect(ch)

    def close(self):
        self.PassThruClose(self.device_id)


# --------------------------------------------------------------------------
# Testroutines
# --------------------------------------------------------------------------

def probe_channel(j, title, proto, baud, set_pin1, listen_s):
    hr(title)
    ch = j.connect(proto, baud)
    if ch is None:
        print("  -> kanaal kon NIET geopend worden (zie foutcode hierboven).")
        return None, 0, {}
    if set_pin1:
        j.set_pin1(ch)
    j.pass_all_filter(ch, proto)
    n, counts = j.listen(ch, listen_s)
    if n == 0:
        print("  geen frames ontvangen in dit venster.")
        print("  (kanaal ging wel open; geen verkeer = contact uit, pin niet "
              "verbonden, of stille bus)")
        print("  tip: contact aan (stand II) + opnieuw; of wek de bus met --active")
    else:
        print(f"  {n} frames ontvangen, {len(counts)} unieke ID's:")
        for cid in sorted(counts):
            print(f"     {id_label(cid):<22} x {counts[cid]}")
    return ch, n, counts


def _open_bus(j, proto, baud, set_pin1=False):
    ch = j.connect(proto, baud)
    if ch is None:
        return None
    if set_pin1:
        j.set_pin1(ch)
    j.pass_all_filter(ch, proto)
    return ch


def _count(j, ch, seconds):
    if ch is None:
        return -1
    return j.listen(ch, seconds)[0]


def _measure(j, specs, seconds):
    """Open alle bussen uit specs [(naam, proto, baud, pin1), ...], luister op
    elk 'seconds' seconden, geef {naam: aantal}. Sluit ALTIJD netjes af en vangt
    fouten af, zodat een crash in 1 fase de rest van de test niet sloopt."""
    chans = []
    counts = {}
    try:
        for name, proto, baud, pin1 in specs:
            counts[name] = -1
            ch = _open_bus(j, proto, baud, pin1)
            chans.append((name, ch))
        for name, ch in chans:
            try:
                counts[name] = _count(j, ch, seconds)
            except Exception as e:
                print(f"      [FOUT bij luisteren op {name}]: {e}")
                counts[name] = -2
    except Exception as e:
        print(f"      [FOUT bij openen van een kanaal]: {e}")
    finally:
        for name, ch in chans:
            try:
                j.disconnect(ch)
            except Exception:
                pass
    return counts


def dual_bus_test(j, seconds):
    """Toetst zuiver (forum, roffe/rogue33): kan de adapter SW-CAN (I-bus) en
    HS-CAN (P-bus) ECHT tegelijk dragen? Elke bus eerst APART (basislijn),
    daarna SAMEN in beide volgordes. Read-only. Crash-vast per fase.
    Tip: voor een eerlijke P-bus-basislijn de motor laten lopen (of contact II)."""
    hr("DUAL-BUS TEST: dragen beide bussen (I-bus + P-bus) tegelijk?")
    I = ("I-bus", PROTO_SW_CAN_PS, 33333, True)
    P = ("P-bus", PROTO_CAN, 500000, False)

    print("  [A] alleen de I-bus (SW-CAN) ...")
    a = _measure(j, [I], seconds)
    print(f"      -> I-bus alleen: {a.get('I-bus')} frames")
    print()

    print("  [B] alleen de P-bus (HS-CAN, 500k) ...")
    b = _measure(j, [P], seconds)
    print(f"      -> P-bus alleen: {b.get('P-bus')} frames")
    print()

    print("  [C] samen - I-bus eerst geopend, dan P-bus erbij ...")
    c = _measure(j, [I, P], seconds)
    print(f"      -> I-bus (beide open): {c.get('I-bus')} frames")
    print(f"      -> P-bus (beide open): {c.get('P-bus')} frames")
    print()

    print("  [D] samen - P-bus eerst geopend, dan I-bus erbij ...")
    d = _measure(j, [P, I], seconds)
    print(f"      -> P-bus (beide open): {d.get('P-bus')} frames")
    print(f"      -> I-bus (beide open): {d.get('I-bus')} frames")
    print()

    sw_alone = a.get("I-bus", -1)
    hs_alone = b.get("P-bus", -1)
    hr("DUAL-BUS OORDEEL")
    print(f"  basislijn   : I-bus alleen = {sw_alone:>6} | P-bus alleen = {hs_alone:>6}")
    print(f"  samen (I 1e): I-bus = {c.get('I-bus'):>6} | P-bus = {c.get('P-bus'):>6}")
    print(f"  samen (P 1e): P-bus = {d.get('P-bus'):>6} | I-bus = {d.get('I-bus'):>6}")
    print("  (-2 = crash/fout bij het lezen van die bus terwijl beide open stonden)")
    print()
    if sw_alone <= 0:
        print("  LET OP: de I-bus gaf al niets apart - contact aan? Eerst 'probe.bat'.")
    if hs_alone <= 0:
        print("  LET OP: de P-bus gaf al niets apart - laat de MOTOR lopen (of contact II).")
    if sw_alone > 0 and hs_alone > 0:
        c_ok = c.get("I-bus", 0) > 0 and c.get("P-bus", 0) > 0
        d_ok = d.get("P-bus", 0) > 0 and d.get("I-bus", 0) > 0
        print()
        if c_ok or d_ok:
            print("  => De adapter houdt BEIDE bussen tegelijk levend. Geschikt voor Tech3Win;")
            print("     Tech3Win's I-Bus Missing ligt dan niet aan dit simultaan-openen.")
        else:
            print("  => Met beide bussen open valt er telkens een stil, of de adapter crasht.")
            print("     De adapter draagt dus in de praktijk maar 1 bus tegelijk - exact de")
            print("     limiet die roffe beschrijft en die de ChipSoft-driver met zoveel")
            print("     woorden noemt. Dit is waarom Tech3Win 'I-Bus Missing' geeft (die opent")
            print("     I-bus, MS-CAN en P-bus tegelijk).")
    print()
    print("  Stuur het logbestand naar Claude.")


def _send_and_watch_cim(j, sw_ch, seconds):
    """Stuur herhaald 241 02 1A 90 op SW-CAN en kijk of de CIM op 641 antwoordt.
    Geeft (got_641, lijst-641-data, totaal_rx, {id:count})."""
    req = make_can_msg(PROTO_SW_CAN_PS, 0x241, bytes([0x02, 0x1A, 0x90]))
    got = False
    replies = []
    ids = {}
    total = 0
    end = time.time() + seconds
    next_send = 0.0
    while time.time() < end:
        now = time.time()
        if now >= next_send:
            if not j.send(sw_ch, req):
                print(f"      [zenden 241 02 1A 90 faalde: {j.last_error()}]")
            next_send = now + 0.5
        arr = (PASSTHRU_MSG * 32)()
        num = c_ulong(32)
        try:
            j.PassThruReadMsgs(sw_ch, arr, byref(num), 150)
        except Exception as e:
            print(f"      [FOUT bij lezen: {e}]")
            break
        for i in range(num.value):
            m = arr[i]
            if m.DataSize >= 4:
                cid = struct.unpack(">I", bytes(m.Data[0:4]))[0] & 0x1FFFFFFF
                ids[cid] = ids.get(cid, 0) + 1
                total += 1
                if cid == 0x641:
                    got = True
                    replies.append(bytes(m.Data[4:m.DataSize]).hex(" "))
    return got, replies, total, ids


def _report_cim(got, replies, total, ids):
    print(f"      641-antwoord van de CIM: {'JA' if got else 'nee'}"
          f"   ({total} frames, {len(ids)} unieke id's)")
    for r in replies[:5]:
        print(f"        641 <- {r}")


def roffe_test(j, seconds):
    """roffe's 3-staps-test: stuur 241 02 1A 90 op SW-CAN (VIN-LEESverzoek aan de
    CIM), verwacht antwoord op 641, in 3 configuraties. Schrijft wel op de bus,
    maar alleen een leesverzoek (1A 90) - geen security access, geen module-write."""
    hr("ROFFE-TEST: 241 02 1A 90 -> CIM, verwacht antwoord op 641")
    res = {}

    hr("Config 1 - SW-CAN alleen, flags 0, pass-all")
    sw = _open_bus(j, PROTO_SW_CAN_PS, 33333, set_pin1=True)
    if sw is not None:
        got, rep, tot, ids = _send_and_watch_cim(j, sw, seconds)
        res[1] = got
        _report_cim(got, rep, tot, ids)
        j.disconnect(sw)
    else:
        res[1] = None
    print()

    hr("Config 2 - zelfde, maar met HS-CAN (500k) er ook bij open")
    hs = _open_bus(j, PROTO_CAN, 500000)
    sw = _open_bus(j, PROTO_SW_CAN_PS, 33333, set_pin1=True)
    if sw is not None:
        got, rep, tot, ids = _send_and_watch_cim(j, sw, seconds)
        res[2] = got
        _report_cim(got, rep, tot, ids)
    else:
        res[2] = None
    j.disconnect(sw)
    j.disconnect(hs)
    print()

    hr("Config 3 - HS open; SW flags 0x800, LOOPBACK 0, filters 540/7E0 + 640/7E0")
    hs = _open_bus(j, PROTO_CAN, 500000)
    sw = j.connect(PROTO_SW_CAN_PS, 33333, flags=CAN_ID_BOTH)
    if sw is not None:
        j.set_pin1(sw)
        j.set_config(sw, LOOPBACK, 0, "SET_CONFIG LOOPBACK=0")
        j.pass_filter(sw, PROTO_SW_CAN_PS, 0x7E0, 0x540)
        j.pass_filter(sw, PROTO_SW_CAN_PS, 0x7E0, 0x640)
        got, rep, tot, ids = _send_and_watch_cim(j, sw, seconds)
        res[3] = got
        _report_cim(got, rep, tot, ids)
    else:
        res[3] = None
    j.disconnect(sw)
    j.disconnect(hs)
    print()

    hr("ROFFE-TEST OORDEEL (zijn eigen interpretatie)")
    def yn(x):
        return "JA (641 gezien)" if x else ("nee" if x is not None else "n.v.t.")
    print(f"  Config 1 (SW alleen)        -> {yn(res.get(1))}")
    print(f"  Config 2 (+ HS-CAN open)    -> {yn(res.get(2))}")
    print(f"  Config 3 (+ flags/filters)  -> {yn(res.get(3))}")
    print()
    r1, r2, r3 = res.get(1), res.get(2), res.get(3)
    if r1 is False:
        print("  => Config 1 faalt: de Nano ZENDT NIET op pin 1 (roffe).")
    elif r2 is False:
        print("  => 1 lukt, 2 faalt: zelfde als de SM2 - de Nano kan geen 2 bussen")
        print("     tegelijk (roffe).")
    elif r3 is False:
        print("  => Alleen 3 faalt: het ligt aan Tech3Win's kant - roffe fixt het.")
    elif r1 and r2 and r3:
        print("  => Alle drie geven 641. De Nano doet alles wat Tech3Win vraagt; het")
        print("     probleem ligt dan subtieler (timing). Stuur roffe deze log.")
    print()
    print("  Stuur het logbestand naar Claude EN naar roffe.")
    print("  Pak na een Tech3Win-run ook C:\\ProgramData\\VCX\\Logs\\VCX\\ mee")
    print("  (VXDIAG's eigen log - daar vroeg roffe om).")


def _pad8(payload):
    """GMLAN-frame op 8 databytes padden (Tech2 vult alles aan met 0x00)."""
    b = bytes(payload)
    return b + b"\x00" * (8 - len(b)) if len(b) < 8 else b


def _send_watch(j, sw_ch, seconds, req_payload, tp_list=None):
    """Stuur herhaald `req_payload` op 0x241 (SW-CAN), optioneel TesterPresent op
    extra kanalen (tp_list = [(ch, proto), ...]), en kijk of de CIM op 641
    antwoordt. Alles wordt op 8 bytes gepadd zoals de Tech2 doet.
    Geeft (got_641, lijst-641-data, totaal_rx, {id:count})."""
    req = make_can_msg(PROTO_SW_CAN_PS, 0x241, _pad8(req_payload))
    tp_msgs = []
    for ch, proto in (tp_list or []):
        tp_msgs.append((ch, make_can_msg(proto, 0x101, _pad8([0xFE, 0x01, 0x3E]))))
    got = False
    replies = []
    ids = {}
    total = 0
    end = time.time() + seconds
    next_send = 0.0
    next_tp = 0.0
    while time.time() < end:
        now = time.time()
        if now >= next_tp and tp_msgs:
            for ch, m in tp_msgs:
                try:
                    j.send(ch, m)               # TesterPresent op alle drie bussen
                except Exception:
                    pass
            next_tp = now + 1.0
        if now >= next_send:
            if not j.send(sw_ch, req):
                print(f"      [zenden verzoek faalde: {j.last_error()}]")
            next_send = now + 0.5
        arr = (PASSTHRU_MSG * 32)()
        num = c_ulong(32)
        try:
            j.PassThruReadMsgs(sw_ch, arr, byref(num), 150)
        except Exception as e:
            print(f"      [FOUT bij lezen: {e}]")
            break
        for i in range(num.value):
            m = arr[i]
            if m.DataSize >= 4:
                cid = struct.unpack(">I", bytes(m.Data[0:4]))[0] & 0x1FFFFFFF
                ids[cid] = ids.get(cid, 0) + 1
                total += 1
                if cid == 0x641:
                    got = True
                    replies.append(bytes(m.Data[4:m.DataSize]).hex(" "))
    return got, replies, total, ids


def _roffe_cfg(j, seconds, label, *, sw_first, hv_wake, third, request):
    """Config 3 als basis, met roffe's vier toevoegingen als aparte schakelaars:
       sw_first  - SW-CAN eerst openen, dan HS (i.p.v. HS eerst)
       hv_wake   - high-voltage wekpuls 0x100 (geen data, TxFlags 0x400) vooraf
       third     - derde kanaal (MS-CAN, CAN_PS 95238, pins 0x030B) + TP op alle 3
       request   - de databytes achter 0x241 (b.v. [0x02,0x1A,0x90] of [0x01,0x20])
    Read-only op modules: alleen een leesverzoek/RTNM + TesterPresent, geen SA."""
    hr(label)
    sw = hs = ms = None

    def open_sw():
        ch = j.connect(PROTO_SW_CAN_PS, 33333, flags=CAN_ID_BOTH)
        if ch is not None:
            j.set_pin1(ch)
            j.set_config(ch, LOOPBACK, 0, "SET_CONFIG LOOPBACK=0")
            j.pass_filter(ch, PROTO_SW_CAN_PS, 0x7E0, 0x540)
            j.pass_filter(ch, PROTO_SW_CAN_PS, 0x7E0, 0x640)
        return ch

    try:
        # 1) openvolgorde
        if sw_first:
            print("  SW-CAN eerst openen ...")
            sw = open_sw()
            print("  dan HS-CAN (500k) ...")
            hs = _open_bus(j, PROTO_CAN, 500000)
        else:
            print("  HS-CAN (500k) eerst openen ...")
            hs = _open_bus(j, PROTO_CAN, 500000)
            print("  dan SW-CAN ...")
            sw = open_sw()
        if sw is None:
            print("  -> SW-CAN ging niet open; config overgeslagen.")
            return None

        # 3) derde kanaal (MS-CAN) vooraf
        tp_list = None
        if third:
            print("  derde kanaal: MS-CAN (CAN_PS 95238, pins 0x030B) ...")
            ms = j.connect(PROTO_CAN_PS, 95238)
            if ms is not None:
                j.set_config(ms, J1962_PINS, 0x030B,
                             "SET_CONFIG J1962_PINS=0x030B (pins 3/11)")
                j.pass_all_filter(ms, PROTO_CAN_PS)
            else:
                print("     (MS-CAN-kanaal ging NIET open - PROTO_CAN_PS/baud? "
                      "zie foutcode; test loopt door, TP alleen op SW+HS.)")
            tp_list = [(c, p) for c, p in
                       ((sw, PROTO_SW_CAN_PS), (hs, PROTO_CAN), (ms, PROTO_CAN_PS))
                       if c is not None]

        # 2) HV-wake vooraf
        if hv_wake:
            wake = make_can_msg(PROTO_SW_CAN_PS, 0x100, b"", txflags=TX_SW_CAN_HV_TX)
            print("  HV-wake 0x100 (geen data, TxFlags 0x400) :",
                  "verstuurd" if j.send(sw, wake) else f"faalde ({j.last_error()})")
            time.sleep(0.1)

        # 4) verzoek + evt. TP op alle bussen, kijk naar 641
        print(f"  verzoek 241 {' '.join(f'{b:02X}' for b in request)} "
              f"(gepadd naar 8) -> luisteren naar 641 ...")
        got, rep, tot, ids = _send_watch(j, sw, seconds, request, tp_list=tp_list)
        _report_cim(got, rep, tot, ids)
        return got
    finally:
        for c in (ms, hs, sw):
            if c is not None:
                try:
                    j.disconnect(c)
                except Exception:
                    pass


def roffe_test2(j, seconds):
    """roffe's vervolg: config 3 draaien met elk van zijn vier toevoegingen,
    los EN alle vier samen, om te zien welke de CIM-antwoord op 641 breekt.
       1. SW-CAN eerst openen (i.p.v. HS eerst)
       2. HV-wake 0x100 vooraf
       3. derde kanaal MS-CAN + TesterPresent op alle drie bussen
       4. verzoek 241 01 20 (verwacht 641 01 60) i.p.v. de VIN-lezing
    Read-only op modules: leesverzoek/RTNM + TesterPresent, geen security access."""
    hr("ROFFE-TEST 2: config 3 + elk van roffe's 4 verschillen, 1 voor 1")
    VIN = [0x02, 0x1A, 0x90]     # 641 <- 5A 90 ...  (VIN-lezing, zoals --roffe)
    RTN = [0x01, 0x20]           # 641 <- 01 60      (ReturnToNormalMode, roffe's #4)
    res = {}

    res["basis"] = _roffe_cfg(
        j, seconds, "Config 3 (herhaling, ter controle: HS eerst, VIN-verzoek)",
        sw_first=False, hv_wake=False, third=False, request=VIN)
    print()
    res["+1 SW-eerst"] = _roffe_cfg(
        j, seconds, "+1  SW-CAN EERST openen, dan HS (VIN-verzoek)",
        sw_first=True, hv_wake=False, third=False, request=VIN)
    print()
    res["+2 HV-wake"] = _roffe_cfg(
        j, seconds, "+2  HV-wake 0x100 vooraf (VIN-verzoek)",
        sw_first=False, hv_wake=True, third=False, request=VIN)
    print()
    res["+3 MS-CAN+TP"] = _roffe_cfg(
        j, seconds, "+3  derde kanaal MS-CAN + TesterPresent op alle 3 (VIN-verzoek)",
        sw_first=False, hv_wake=False, third=True, request=VIN)
    print()
    res["+4 241 01 20"] = _roffe_cfg(
        j, seconds, "+4  verzoek 241 01 20, verwacht 641 01 60",
        sw_first=False, hv_wake=False, third=False, request=RTN)
    print()
    res["alles samen"] = _roffe_cfg(
        j, seconds, "ALLES SAMEN (SW-eerst + HV-wake + MS-CAN/TP + 241 01 20) "
        "= volledige Tech3Win-replica",
        sw_first=True, hv_wake=True, third=True, request=RTN)
    print()

    hr("ROFFE-TEST 2 OORDEEL")
    def yn(x):
        return "JA (641 gezien)" if x else ("nee" if x is not None else "n.v.t.")
    for name in ("basis", "+1 SW-eerst", "+2 HV-wake", "+3 MS-CAN+TP",
                 "+4 241 01 20", "alles samen"):
        print(f"  {name:<14} -> {yn(res.get(name))}")
    print()
    losers = [n for n in ("+1 SW-eerst", "+2 HV-wake", "+3 MS-CAN+TP", "+4 241 01 20")
              if res.get(n) is False]
    if res.get("basis") is False:
        print("  => Zelfs de herhaling van config 3 geeft nu geen 641. Eerst dat")
        print("     uitzoeken (contact aan? Nano via VX Manager gewekt?) voor de rest")
        print("     iets zegt.")
    elif losers:
        print("  => Dit breekt het 641-antwoord: " + ", ".join(losers) + ".")
        print("     Dat is precies de toevoeging die Tech3Win's I-Bus Missing veroorzaakt.")
    elif res.get("alles samen") is False:
        print("  => Elk verschil apart is OK, maar alles samen breekt het. Dan zit het")
        print("     in de combinatie/timing, niet in 1 losse stap.")
    else:
        print("  => Alle varianten geven 641, ook de volledige Tech3Win-replica. De")
        print("     adapter doet letterlijk alles wat Tech3Win doet; het verschil zit")
        print("     dan in HOE/ WANNEER Tech3Win het aanstuurt, niet in WAT.")
    print()
    print("  Stuur deze log naar roffe, EN pak uit dezelfde map (na deze run):")
    print("     C:\\ProgramData\\VCX\\Logs\\VCX\\VCX.python.exe.log")
    print("  Daar vroeg roffe expliciet om (naast de tech3win-log).")


def sniff_bus(j, do_hs):
    """PASSIEVE opname. Opent SW-CAN (I-bus) alleen-luisteren en logt ELK frame
    met een tijdstempel naar een CSV naast dit script. Stuurt NIETS naar de bus
    (geen wek, geen TesterPresent, geen verzoek) - veilig om naast een ander
    apparaat (bv. een fysieke Tech2) mee te lezen. Met --hs ook HS-CAN (P-bus).
    Stoppen met Ctrl+C; de CSV wordt netjes afgesloten.

    De interessante frames (3B schrijven, 7F weigering, 27 security access) komen
    ook live op het scherm; de rest gaat alleen naar de CSV (zodat het scherm de
    opname niet vertraagt)."""
    hr("SNIFFER (passief) - logt ALLE frames, STUURT NIETS. Stop met Ctrl+C")

    csv_path = None
    csv = None
    try:
        d = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(d, time.strftime("sniff_%Y-%m-%d_%H%M%S.csv"))
        csv = open(csv_path, "w", encoding="utf-8", buffering=1)
        csv.write("time_s,bus,id_hex,module,dlc,data_hex\n")
        print(f"  Opname-CSV: {csv_path}")
    except Exception as e:
        print(f"  (kon geen CSV openen: {e}; alleen het .log-bestand wordt gevuld)")
        csv = None

    chans = []
    sw = j.connect(PROTO_SW_CAN_PS, 33333, flags=CAN_ID_BOTH)
    if sw is None:
        print("  SW-CAN ging niet open; stop.")
        if csv:
            csv.close()
        return
    j.set_pin1(sw)
    j.set_config(sw, LOOPBACK, 0, "SET_CONFIG LOOPBACK=0")
    j.pass_all_filter(sw, PROTO_SW_CAN_PS)
    chans.append((sw, "I"))
    print("  SW-CAN (I-bus, pin 1, 33333) open - ALLEEN LUISTEREN")
    hs = None
    if do_hs:
        hs = _open_bus(j, PROTO_CAN, 500000)
        if hs is not None:
            chans.append((hs, "P"))
            print("  HS-CAN (P-bus, 500k) open - ALLEEN LUISTEREN")

    print()
    print("  >>> START NU je Tech2-actie (Remove/Add). Alles wordt opgenomen.  <<<")
    print("  >>> Klaar? Ctrl+C om te stoppen en de CSV af te sluiten.          <<<")
    print()

    t0 = time.time()
    total = 0
    ids = {}
    last_status = 0.0
    BATCH = 64
    try:
        while True:
            got_any = False
            for ch, tag in chans:
                arr = (PASSTHRU_MSG * BATCH)()
                num = c_ulong(BATCH)
                try:
                    j.PassThruReadMsgs(ch, arr, byref(num), 50)
                except Exception:
                    num.value = 0
                for i in range(num.value):
                    m = arr[i]
                    if m.DataSize < 4:
                        continue
                    got_any = True
                    cid = struct.unpack(">I", bytes(m.Data[0:4]))[0] & 0x1FFFFFFF
                    data = bytes(m.Data[4:m.DataSize])
                    t = time.time() - t0
                    total += 1
                    ids[cid] = ids.get(cid, 0) + 1
                    mod = KNOWN_IDS.get(cid, "")
                    hexd = data.hex(" ")
                    if csv:
                        csv.write(f"{t:.3f},{tag},{cid:03X},{mod},{len(data)},{hexd}\n")
                    # alleen de interessante frames op het scherm
                    if len(data) >= 2 and data[1] in (0x3B, 0x7F, 0x27):
                        svc = {0x3B: "WRITE 3B", 0x7F: "NEG 7F",
                               0x27: "SEC 27"}[data[1]]
                        extra = f" [{mod}]" if mod else ""
                        print(f"  t={t:8.3f} [{tag}] {cid:03X}{extra}  {hexd}   <-- {svc}")
            now = time.time()
            if now - last_status >= 2.0:
                print(f"  --- opgenomen: {total} frames, {len(ids)} id's, "
                      f"{now - t0:.0f}s (Ctrl+C = stop) ---")
                last_status = now
            if not got_any:
                time.sleep(0.005)
    except KeyboardInterrupt:
        pass
    finally:
        for ch, _ in chans:
            try:
                j.disconnect(ch)
            except Exception:
                pass
        if csv:
            try:
                csv.close()
            except Exception:
                pass

    print()
    hr("SNIFFER GESTOPT")
    print(f"  Totaal {total} frames, {len(ids)} unieke id's, "
          f"{time.time() - t0:.0f}s opgenomen.")
    if ids:
        top = sorted(ids.items(), key=lambda kv: -kv[1])[:10]
        print("  Meest gezien:", ", ".join(
            f"{i:03X}{('(' + KNOWN_IDS[i] + ')') if i in KNOWN_IDS else ''}x{n}"
            for i, n in top))
    if csv_path:
        print(f"\n  >>> STUUR DIT CSV-BESTAND naar Claude: {csv_path}")
        print("      (CSV is tekst en overleeft de chat-upload prima.)")
    print("  Tip: zoek in de CSV naar '3b ba' (de BCM bus-config-schrijfactie)")
    print("       en naar '7f 3b' (een weigering) om de BCM-stap terug te vinden.")


def active_wake_and_testerpresent(j, ch, seconds, do_hv_wake):
    """ALLEEN met --active. Stuurt de GMLAN wake/TesterPresent zoals oamne's
    agent. GEEN security access, GEEN Add/Remove, GEEN module-schrijfacties."""
    hr("ACTIEF: GMLAN wake + TesterPresent (schrijft op de bus)")
    if do_hv_wake:
        wake = make_can_msg(PROTO_SW_CAN_PS, 0x100, b"", txflags=TX_SW_CAN_HV_TX)
        print("  high-voltage wekpuls 0x100 :",
              "verstuurd" if j.send(ch, wake) else f"faalde ({j.last_error()})")
        time.sleep(0.1)
    wul = make_can_msg(PROTO_SW_CAN_PS, 0x101, bytes([0xFD, 0x02, 0x10, 0x04]))
    print("  wakeUpLinks 0x101 FD 02 10 04 :",
          "verstuurd" if j.send(ch, wul) else f"faalde ({j.last_error()})")
    time.sleep(0.1)
    tp = make_can_msg(PROTO_SW_CAN_PS, 0x101, bytes([0xFE, 0x01, 0x3E]))
    counts = {}
    n_total = 0
    end = time.time() + seconds
    while time.time() < end:
        j.send(ch, tp)                       # TesterPresent FE 01 3E
        arr = (PASSTHRU_MSG * 32)()
        num = c_ulong(32)
        j.PassThruReadMsgs(ch, arr, byref(num), 400)
        for i in range(num.value):
            m = arr[i]
            if m.DataSize >= 4:
                cid = struct.unpack(">I", bytes(m.Data[0:4]))[0] & 0x1FFFFFFF
                counts[cid] = counts.get(cid, 0) + 1
                n_total += 1
        time.sleep(1.0)
    # netjes afsluiten: ReturnToNormalMode
    rtn = make_can_msg(PROTO_SW_CAN_PS, 0x101, bytes([0xFE, 0x01, 0x20]))
    j.send(ch, rtn)
    if n_total == 0:
        print("  geen antwoorden ontvangen op de wake/TesterPresent.")
    else:
        print(f"  {n_total} frames ontvangen, {len(counts)} unieke ID's:")
        for cid in sorted(counts):
            print(f"     {id_label(cid):<22} x {counts[cid]}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="J2534 Nano Probe - test of de Nano single-wire CAN kan voor Tech3Win.")
    ap.add_argument("--dll", help="pad naar de J2534-DLL (anders: kies uit de registry)")
    ap.add_argument("--seconds", type=int, default=8,
                    help="hoe lang passief luisteren per kanaal (standaard 8)")
    ap.add_argument("--hs", action="store_true",
                    help="ook een HS-CAN-kanaal (500k) proberen")
    ap.add_argument("--active", action="store_true",
                    help="GMLAN wake + TesterPresent sturen (schrijft op de bus; "
                         "geen SA/Add-Remove). Standaard UIT.")
    ap.add_argument("--hv-wake", action="store_true",
                    help="met --active ook de high-voltage wekpuls 0x100 sturen")
    ap.add_argument("--dual", action="store_true",
                    help="dual-bus test: kan de Nano SW-CAN en HS-CAN echt tegelijk? "
                         "(leest de I-bus voor en na het openen van de P-bus)")
    ap.add_argument("--roffe", action="store_true",
                    help="roffe's 3-staps-test: stuurt 241 02 1A 90 naar de CIM en "
                         "kijkt of die op 641 antwoordt, in 3 configuraties")
    ap.add_argument("--roffe2", action="store_true",
                    help="roffe's vervolg: config 3 met elk van zijn 4 verschillen "
                         "(SW-eerst, HV-wake, MS-CAN+TP, 241 01 20) los en samen")
    ap.add_argument("--sniff", action="store_true",
                    help="PASSIEVE opname: logt alle I-bus-frames (met --hs ook "
                         "P-bus) naar een CSV, stuurt zelf NIETS; om een fysieke "
                         "Tech2-sessie mee te lezen. Stop met Ctrl+C")
    args = ap.parse_args()

    _start_logging()  # vanaf hier gaat alles ook naar een logbestand

    print("=" * 70)
    print("  J2534 NANO PROBE  -  VCX Nano / Tech3Win haalbaarheidstest")
    print("=" * 70)
    if _LOGPATH:
        print(f"Logbestand: {_LOGPATH}")

    # 1) 32-bit-check
    bits = struct.calcsize("P") * 8
    print(f"Python: {sys.version.split()[0]}  ({bits}-bit)")
    if bits != 32:
        print()
        print("!! Dit is 64-bit Python. J2534-driver-DLL's zijn 32-bit en kunnen")
        print("!! hiermee NIET geladen worden. Start opnieuw met 32-bit Python")
        print("!! (zie LEESMIJ.txt). De registry-lijst hieronder werkt nog wel.")
        print()

    # 2) Registry (werkt zonder hardware)
    hr("STAP 1  Geregistreerde J2534-drivers (uit de Windows-registry)")
    regs = read_registry()
    if not regs:
        print("  Geen J2534 04.04-drivers geregistreerd gevonden.")
        print("  -> Is VX Manager geinstalleerd op deze machine?")
    else:
        for idx, r in enumerate(regs):
            caps = [k for k, v in r["caps"].items() if str(v) in ("1", "True")]
            sw = "SW_CAN_PS" in r["caps"]
            print(f"  [{idx}] {r['Name'] or r['regkey']}")
            print(f"       DLL : {r['FunctionLibrary']}")
            if caps:
                print(f"       kan : {', '.join(sorted(caps))}")
            flag = "JA" if sw else "NIET vermeld"
            print(f"       -> single-wire CAN (SW_CAN_PS) in registry: {flag}")
    print()

    if bits != 32:
        print("Gestopt na de registry-lijst (64-bit Python kan de DLL niet laden).")
        return _pause()

    # 3) Kies DLL
    dll_path = args.dll
    if not dll_path:
        if not regs:
            print("Geen DLL opgegeven en niets in de registry. Gebruik --dll <pad>.")
            return _pause()
        # voorkeur: VXDIAG (= de Nano) met SW_CAN_PS; anders eerste met SW_CAN_PS; anders eerste
        def is_vxdiag(r):
            hay = (r["Name"] + " " + r["FunctionLibrary"]).upper()
            return "VXDIAG" in hay or "\\VCX\\" in hay.replace("/", "\\")
        pick = (next((r for r in regs if is_vxdiag(r) and "SW_CAN_PS" in r["caps"]), None)
                or next((r for r in regs if "SW_CAN_PS" in r["caps"]), None)
                or regs[0])
        dll_path = pick["FunctionLibrary"]
        print(f"Gekozen driver: {pick['Name'] or pick['regkey']}")
        print("(een andere kiezen kan met --dll <pad>, b.v. de VXDIAG VCXPT32.dll)")
    print(f"DLL: {dll_path}")
    if not os.path.isfile(dll_path):
        print("!! Dit DLL-pad bestaat niet. Controleer VX Manager / het pad.")
        return _pause()
    print()

    # 4) Open + versie + accuspanning
    hr("STAP 2  Driver openen")
    try:
        j = J2534(dll_path)
    except OSError as e:
        print(f"  [FOUT] kan de DLL niet laden: {e}")
        print("  (meestal: 64-bit Python tegen een 32-bit DLL, of ontbrekende "
              "afhankelijkheid/driver)")
        return _pause()
    if not j.open():
        print("  Kon de adapter niet openen. Zit de Nano aangesloten en herkend?")
        return _pause()
    j.version()
    j.vbatt()
    print()

    # 4b) dual-bus test (aparte modus): doet de Nano SW-CAN en HS-CAN tegelijk?
    if args.dual:
        dual_bus_test(j, max(args.seconds, 5))
        j.close()
        return _pause()

    # 4c) roffe's 3-staps-test (aparte modus)
    if args.roffe:
        roffe_test(j, max(args.seconds, 5))
        j.close()
        return _pause()

    # 4d) roffe's vervolg-test: config 3 + zijn 4 verschillen (aparte modus)
    if args.roffe2:
        roffe_test2(j, max(args.seconds, 5))
        j.close()
        return _pause()

    # 4e) passieve sniffer (aparte modus): logt alles naar CSV, stuurt niets
    if args.sniff:
        sniff_bus(j, args.hs)
        j.close()
        return _pause()

    # 5) SW_CAN_PS - DE kernvraag
    sw_ch, sw_n, _ = probe_channel(
        j, "STAP 3  SINGLE-WIRE CAN (SW_CAN_PS, pin 1, 33.333) - de kernvraag",
        PROTO_SW_CAN_PS, 33333, set_pin1=True, listen_s=args.seconds)

    # 6) optioneel HS-CAN
    hs_ch = None
    if args.hs:
        hs_ch, _, _ = probe_channel(
            j, "STAP 4  HS-CAN (raw CAN, 500k) - controle",
            PROTO_CAN, 500000, set_pin1=False, listen_s=args.seconds)

    # 7) optioneel actief
    if args.active:
        if sw_ch is not None:
            active_wake_and_testerpresent(j, sw_ch, max(args.seconds, 6),
                                          do_hv_wake=args.hv_wake)
        else:
            print("  (--active overgeslagen: het SW_CAN_PS-kanaal ging niet open)")

    # 8) netjes sluiten
    j.disconnect(sw_ch)
    j.disconnect(hs_ch)
    j.close()

    # 9) Eindoordeel
    hr("SAMENVATTING")
    reg_sw = any("SW_CAN_PS" in r["caps"] for r in regs)
    print(f"  Registry meldt SW_CAN_PS        : {'JA' if reg_sw else 'nee / niet vermeld'}")
    print(f"  SW_CAN_PS-kanaal ging open      : {'JA' if sw_ch is not None else 'NEE'}")
    print(f"  Frames op de I-bus gezien       : {'JA (' + str(sw_n) + ')' if sw_n else 'nee'}")
    print()
    if sw_ch is not None and sw_n > 0:
        print("  => Sterkste uitkomst: de Nano-driver geeft een single-wire kanaal")
        print("     EN er is I-bus-verkeer. Dit is precies wat Tech3Win vraagt.")
    elif sw_ch is not None:
        print("  => Het single-wire kanaal GING OPEN (de driver kan het), maar er")
        print("     kwam geen verkeer. Zet het contact aan en probeer opnieuw;")
        print("     blijft het leeg, dan is het de bedrading naar pin 1.")
    else:
        print("  => Het single-wire kanaal ging NIET open. Stuur mij de volledige")
        print("     uitvoer (vooral de foutcodes en -teksten); dan kijken we of het")
        print("     aan een constante (protocol-id/pin) of aan de driver ligt.")
    print()
    print("  Stuur de hele uitvoer naar Claude om de volgende stap te bepalen.")
    _pause()


class _Tee:
    """Schrijft alle uitvoer tegelijk naar het scherm EN naar een logbestand."""
    def __init__(self, *streams):
        self.streams = streams
    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
            except Exception:
                pass
    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


_LOGPATH = None


def _start_logging():
    """Begin alles mee te schrijven naar een logbestand naast dit script."""
    global _LOGPATH
    try:
        d = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(d, time.strftime("probe_%Y-%m-%d_%H%M%S.log"))
        # buffering=1 = regelgebufferd: elke regel wordt meteen weggeschreven,
        # zodat de log ook bij een crash (bv. in de adapter-DLL) compleet is.
        f = open(path, "w", encoding="utf-8", buffering=1)
        sys.stdout = _Tee(sys.__stdout__, f)
        _LOGPATH = path
    except Exception:
        _LOGPATH = None


def _pause():
    if _LOGPATH:
        print(f"\n(Deze uitvoer is ook opgeslagen in:\n  {_LOGPATH}\n"
              " -> stuur dat bestand naar Claude; kopieren/plakken hoeft niet.)")
    try:
        sys.stdout.flush()
    except Exception:
        pass
    try:
        input("\nDruk op Enter om te sluiten...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
