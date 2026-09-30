#!/usr/bin/env python3
"""
ha_netscan.py – Netzwerk-Inventar mit Home-Assistant-Integrationsvorschlägen
===========================================================================

Scannt ein Subnetz, erkennt Geräte und Protokolle und schlägt passende
Home-Assistant-Integrationen vor (Core, HACS, GitHub-Suche).

Nur Python-Standardbibliothek, keine Installation nötig (Python 3.9+).

Beispiele:
    python3 ha_netscan.py
    python3 ha_netscan.py --subnet 192.168.50.0/24
    HA_TOKEN=eyJ... python3 ha_netscan.py --ha-url http://192.168.50.10:8123

Datenquellen (werden beim ersten Lauf geladen und 7 Tage zwischengespeichert):
  * Home Assistant Core: generated/dhcp.py, zeroconf.py, ssdp.py, integrations.json
  * HACS: data-v2.hacs.xyz (Fallback: Liste aus github.com/hacs/default)
  * MAC-Hersteller: Wireshark-"manuf"-Datei (Fallback: IEEE oui.csv)

Hinweis: Das Skript fragt nur offene Ports ab und liest Web-Seiten-Titel.
Modbus-Register werden bewusst NICHT abgefragt.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import csv
import errno
import fnmatch
import html
import io
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

VERSION = "0.7"
DEFAULT_SUBNET = "192.168.50.0/24"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "ha_netscan")
CACHE_MAX_AGE = 7 * 24 * 3600
UA = f"ha_netscan/{VERSION}"

HA_GEN = "https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/"
SOURCES = {
    "dhcp.py": [HA_GEN + "dhcp.py"],
    "zeroconf.py": [HA_GEN + "zeroconf.py"],
    "ssdp.py": [HA_GEN + "ssdp.py"],
    "integrations.json": [HA_GEN + "integrations.json"],
    "hacs_data.json": ["https://data-v2.hacs.xyz/integration/data.json"],
    "hacs_list.json": ["https://raw.githubusercontent.com/hacs/default/master/integration"],
    "manuf": ["https://www.wireshark.org/download/automated/data/manuf"],
    "oui.csv": ["https://standards-oui.ieee.org/oui/oui.csv"],
}

# Ports, die geprüft werden: Port -> Bezeichnung
PORTS = {
    80: "HTTP",
    443: "HTTPS",
    502: "Modbus TCP",
    554: "RTSP (Kamera)",
    1400: "Sonos",
    1883: "MQTT-Broker",
    8883: "MQTT-Broker (TLS)",
    5000: "HTTP-Alt / Synology",
    5001: "HTTPS-Alt / Synology",
    6053: "ESPHome API",
    6668: "Tuya lokal",
    8008: "Google Cast",
    8009: "Google Cast",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt",
    8123: "Home Assistant",
    8443: "HTTPS-Alt",
    9000: "HTTP-Alt",
}
HTTP_PORTS = [80, 8080, 8081, 9000, 5000]

# Chip-/Modul-Hersteller: sagen nichts über das eigentliche Produkt aus
CHIP_VENDORS = {
    "espressif", "realtek", "murata", "azurewave", "hon", "liteon", "lite-on",
    "silicon", "texas", "beken", "high-flying", "hi-flying", "bouffalo",
    "universal", "mediatek", "qualcomm", "broadcom", "intel", "raspberry",
    "cypress", "microchip", "nordic", "winner", "amlogic", "rockchip",
    "cloud", "private", "ieee", "tenda", "zte", "askey", "sagemcom", "chongqing",
}
# Städte-/Rechtsform-Wörter, die bei Herstellernamen übersprungen werden
VENDOR_SKIP_WORDS = {
    "shenzhen", "hangzhou", "guangzhou", "beijing", "shanghai", "zhejiang",
    "xiamen", "ningbo", "suzhou", "dongguan", "jiangsu", "qingdao", "chengdu",
    "the", "co", "ltd", "inc", "gmbh", "ag", "corp", "corporation", "technology",
    "technologies", "electronics", "electronic", "communication", "international",
}
# Herstellername -> besserer Suchbegriff
VENDOR_ALIASES = {
    "allterco": "shelly", "signify": "hue", "philips": "hue", "avm": "fritz",
    "tp-link": "tp-link", "tplink": "tp-link", "ubiquiti": "unifi",
    "sonos": "sonos", "hikvision": "hikvision", "xiaomi": "xiaomi",
    "amazon": "alexa", "google": "google", "apple": "apple",
    "huawei": "huawei", "sma": "sma", "fronius": "fronius", "tuya": "tuya",
    "hame": "marstek", "marstek": "marstek", "asustek": "asus", "asus": "asus",
}


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------

def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


LOG_SINK = _stderr  # wird von der HA-Integration durch den HA-Logger ersetzt


def log(msg: str) -> None:
    LOG_SINK(msg)


# Für Adressen im Heimnetz: niemals über einen (Firmen-)Proxy gehen
LAN = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_get(url: str, timeout: float = 20, headers: dict | None = None,
             lan: bool = False) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    opener = LAN.open if lan else urllib.request.urlopen
    with opener(req, timeout=timeout) as r:
        return r.read()


def fetch_source(name: str, refresh: bool = False) -> bytes | None:
    """Lädt eine Datenquelle (mit Cache). Gibt None zurück, wenn nicht verfügbar."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, name)
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < CACHE_MAX_AGE
    if fresh and not refresh:
        with open(path, "rb") as f:
            return f.read()
    for url in SOURCES[name]:
        try:
            data = http_get(url, timeout=60)
            if data:
                with open(path, "wb") as f:
                    f.write(data)
                return data
        except Exception as e:  # noqa: BLE001
            log(f"  ! {name}: Download fehlgeschlagen ({e.__class__.__name__})")
    if os.path.exists(path):
        log(f"  ! {name}: verwende ältere Kopie aus dem Cache")
        with open(path, "rb") as f:
            return f.read()
    return None


def literal_from_py(source: bytes, varname: str):
    """Liest eine Konstante (z. B. DHCP = [...]) aus einer generated/*.py-Datei."""
    tree = ast.parse(source.decode("utf-8"))
    for node in tree.body:
        target = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if isinstance(target, ast.Name) and target.id == varname:
            return ast.literal_eval(node.value)
    return None


def norm_mac(mac: str) -> str | None:
    parts = re.split(r"[:\-.]", mac.strip())
    if len(parts) == 6:
        try:
            return ":".join(f"{int(p, 16):02X}" for p in parts)
        except ValueError:
            return None
    if len(parts) == 3:  # Cisco-Format aaaa.bbbb.cccc
        s = "".join(parts)
        if len(s) == 12:
            return ":".join(s[i:i + 2] for i in range(0, 12, 2)).upper()
    return None


def is_random_mac(mac: str) -> bool:
    return bool(mac) and int(mac[1], 16) & 0x2 == 0x2


# --------------------------------------------------------------------------
# Datenmodell
# --------------------------------------------------------------------------

@dataclass
class Suggestion:
    kind: str            # core | hacs | github | info
    title: str
    domain: str = ""
    url: str = ""
    extra_url: str = ""
    reason: str = ""
    confidence: int = 50  # 0..100
    installed: bool = False
    stars: int = 0
    upgrade: bool = False  # optionale Verbesserung, keine offene Baustelle


@dataclass
class Host:
    ip: str
    alive: bool = False
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list = field(default_factory=list)
    mdns: dict = field(default_factory=dict)       # type -> [ {name, props} ]
    ssdp: list = field(default_factory=list)       # [ {headers..., desc...} ]
    http: dict = field(default_factory=dict)       # port -> {title, server, probes}
    suggestions: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def display_name(self) -> str:
        for entries in self.mdns.values():
            for e in entries:
                if e.get("name"):
                    return e["name"]
        for s in self.ssdp:
            if s.get("friendlyName"):
                return s["friendlyName"]
        if self.hostname:
            return self.hostname
        for h in self.http.values():
            if h.get("title"):
                return h["title"]
        return ""

    @property
    def protocols(self) -> list:
        out = [PORTS.get(p, str(p)) + f" ({p})" for p in sorted(self.ports)]
        for t in sorted(self.mdns):
            out.append("mDNS " + t.replace(".local.", ""))
        if self.ssdp:
            out.append("UPnP/SSDP")
        return out


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

def probe_port(ip: str, port: int, timeout: float) -> tuple[str, int, str]:
    """Rückgabe: (ip, port, 'open' | 'refused' | 'closed')"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
        if rc == 0:
            return ip, port, "open"
        if rc in (errno.ECONNREFUSED, 10061):
            return ip, port, "refused"  # Host lebt, Port zu
        return ip, port, "closed"
    except OSError:
        return ip, port, "closed"
    finally:
        s.close()


def port_scan(hosts: dict, ips: list, timeout: float, workers: int) -> None:
    jobs = [(ip, p) for ip in ips for p in PORTS]
    random.shuffle(jobs)  # verteilt Last auf die Geräte
    done = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(probe_port, ip, p, timeout) for ip, p in jobs]
        for fut in cf.as_completed(futs):
            ip, port, state = fut.result()
            done += 1
            if done % 500 == 0:
                log(f"  … {done}/{len(jobs)} Port-Proben")
            if state in ("open", "refused"):
                h = hosts.setdefault(ip, Host(ip))
                h.alive = True
                if state == "open":
                    h.ports.append(port)


def read_arp_table() -> dict:
    """IP -> MAC aus der ARP-/Neighbour-Tabelle des Betriebssystems."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                cols = line.split()
                if len(cols) >= 4 and cols[2] != "0x0":
                    mac = norm_mac(cols[3])
                    if mac and mac != "00:00:00:00:00:00":
                        table[cols[0]] = mac
        if table:
            return table
    if os.name == "nt":
        cmds = [["arp", "-a"]]
    else:
        cmds = [["ip", "neigh"], ["arp", "-an"], ["arp", "-a"]]
    for cmd in cmds:
        try:
            raw = subprocess.run(cmd, capture_output=True, timeout=10).stdout or b""
        except Exception:  # noqa: BLE001
            continue
        out = raw.decode("utf-8", "replace") if raw else ""
        for line in out.splitlines():
            if re.search(r"arp\s+-", line, re.I):
                continue  # Hilfetext/Beispiele überspringen
            ipm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            macm = re.search(r"((?:[0-9A-Fa-f]{1,2}[:\-]){5}[0-9A-Fa-f]{1,2})", line)
            if ipm and macm:
                mac = norm_mac(macm.group(1))
                if mac and mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    table[ipm.group(1)] = mac
        if table:
            break
    return table


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


# ---- mDNS ----------------------------------------------------------------

def _dns_name(data: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(64):
        if off >= len(data):
            break
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(data[off + 1: off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels) + ".", (end if jumped else off)


def _dns_query(names: list[str]) -> bytes:
    pkt = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    for n in names:
        for lab in n.rstrip(".").split("."):
            b = lab.encode()
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack("!HH", 12, 0x8001)  # PTR, QU-Bit
    return pkt


def _parse_dns(data: bytes) -> list[dict]:
    recs = []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = _dns_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[off: off + 10])
            off += 10
            rd = data[off: off + rdlen]
            rec = {"name": name, "type": rtype}
            if rtype == 12:  # PTR
                rec["ptr"] = _dns_name(data, off)[0]
            elif rtype == 16:  # TXT
                props, i = {}, 0
                while i < len(rd):
                    ln = rd[i]
                    kv = rd[i + 1: i + 1 + ln].decode("utf-8", "replace")
                    i += 1 + ln
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        props[k.lower()] = v
                    elif kv:
                        props[kv.lower()] = ""
                rec["txt"] = props
            elif rtype == 33:  # SRV
                rec["port"] = struct.unpack("!H", rd[4:6])[0]
                rec["target"] = _dns_name(data, off + 6)[0]
            elif rtype == 1 and rdlen == 4:  # A
                rec["a"] = socket.inet_ntoa(rd)
            recs.append(rec)
            off += rdlen
    except Exception:  # noqa: BLE001
        pass
    return recs


def _mdns_round(names: list[str], wait: float) -> list[tuple[str, list]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.settimeout(0.3)
    out = []
    try:
        for i in range(0, len(names), 10):
            s.sendto(_dns_query(names[i:i + 10]), ("224.0.0.251", 5353))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(9000)
                out.append((src, _parse_dns(data)))
            except (socket.timeout, OSError):
                continue
    except OSError as e:
        log(f"  ! mDNS nicht möglich: {e}")
    finally:
        s.close()
    return out


def mdns_scan(wait: float = 3.0) -> dict:
    """Rückgabe: ip -> {service_type: [ {name, props} ]}"""
    types = set()
    for _, recs in _mdns_round(["_services._dns-sd._udp.local."], wait):
        for r in recs:
            if r["type"] == 12 and r["name"].startswith("_services._dns-sd"):
                types.add(r["ptr"])
    types.update({"_hap._tcp.local.", "_http._tcp.local.", "_esphomelib._tcp.local.",
                  "_shelly._tcp.local.", "_hue._tcp.local.", "_googlecast._tcp.local.",
                  "_airplay._tcp.local.", "_matter._tcp.local.", "_miio._udp.local.",
                  "_wled._tcp.local.", "_sonos._tcp.local.", "_spotify-connect._tcp.local."})
    result: dict = {}
    responses = _mdns_round(sorted(types), wait + 1)
    a_records = {}
    for _, recs in responses:
        for r in recs:
            if "a" in r:
                a_records[r["name"].lower()] = r["a"]
    for src, recs in responses:
        txt = {r["name"].lower(): r["txt"] for r in recs if "txt" in r}
        srv = {r["name"].lower(): r["target"].lower() for r in recs if "target" in r}
        for r in recs:
            if r["type"] != 12 or r["name"].startswith("_services._dns-sd"):
                continue
            stype, inst = r["name"], r["ptr"]
            if not stype.endswith(".local."):
                continue
            ip = a_records.get(srv.get(inst.lower(), ""), src)
            short = inst[: -len(stype)].rstrip(".") if inst.endswith(stype) else inst
            entry = {"name": short.replace("\\032", " "), "props": txt.get(inst.lower(), {})}
            lst = result.setdefault(ip, {}).setdefault(stype, [])
            if entry["name"] not in [e["name"] for e in lst]:
                lst.append(entry)
    return result


# ---- SSDP ----------------------------------------------------------------

def ssdp_scan(wait: float = 4.0) -> dict:
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    s.settimeout(0.3)
    raw: dict = {}
    try:
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            hdr = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            raw.setdefault(src, []).append(hdr)
    except OSError as e:
        log(f"  ! SSDP nicht möglich: {e}")
    finally:
        s.close()

    result: dict = {}
    desc_cache: dict = {}
    for ip, hdrs in raw.items():
        for hdr in hdrs:
            loc = hdr.get("location", "")
            if loc and loc not in desc_cache:
                desc_cache[loc] = _ssdp_description(loc)
            entry = {"st": hdr.get("st", ""), "usn": hdr.get("usn", ""),
                     "server": hdr.get("server", ""), "location": loc}
            entry.update(desc_cache.get(loc, {}))
            result.setdefault(ip, []).append(entry)
    return result


def _ssdp_description(url: str) -> dict:
    try:
        root = ET.fromstring(http_get(url, timeout=3, lan=True))
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("friendlyName", "manufacturer", "manufacturerURL", "modelName",
                   "modelNumber", "modelDescription", "deviceType", "serialNumber",
                   "UDN") and tag not in out and el.text:
            out[tag] = el.text.strip()
    return out


# ---- HTTP-Fingerprints ---------------------------------------------------

def http_fingerprint(ip: str, port: int) -> dict:
    base = f"http://{ip}" + ("" if port == 80 else f":{port}")
    info: dict = {"probes": {}}
    try:
        req = urllib.request.Request(base + "/", headers={"User-Agent": UA})
        with LAN.open(req, timeout=3) as r:
            info["server"] = r.headers.get("Server", "")
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        info["server"] = e.headers.get("Server", "") if e.headers else ""
        body = ""
    except Exception:  # noqa: BLE001
        body = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        info["title"] = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:80]
    info["body_hint"] = body[:4000].lower()
    if port == 80:
        for path in ("/shelly", "/json/info", "/solar_api/GetAPIVersion.cgi"):
            try:
                with LAN.open(base + path, timeout=2) as r:
                    txt = r.read(8192).decode("utf-8", "replace")
                    info["probes"][path] = json.loads(txt)
            except Exception:  # noqa: BLE001
                pass
    return info


# --------------------------------------------------------------------------
# Wissensbasis
# --------------------------------------------------------------------------

class Knowledge:
    def __init__(self, refresh: bool = False, cache_dir: str | None = None):
        global CACHE_DIR
        if cache_dir:
            CACHE_DIR = cache_dir
        self.loaded_at = time.time()
        log(f"ha_netscan {VERSION} – lade Datenquellen …")
        self.dhcp = []
        self.zeroconf = {}
        self.homekit = {}
        self.ssdp = {}
        self.core: dict = {}      # domain -> {name, config_flow, iot_class}
        self.hacs: list = []      # [ {full_name, name, description, domain, stars, topics} ]
        self.oui: dict = {}       # prefix-bits -> {(prefix): name}

        src = fetch_source("dhcp.py", refresh)
        if src:
            self.dhcp = literal_from_py(src, "DHCP") or []
        src = fetch_source("zeroconf.py", refresh)
        if src:
            self.zeroconf = literal_from_py(src, "ZEROCONF") or {}
            self.homekit = literal_from_py(src, "HOMEKIT") or {}
        src = fetch_source("ssdp.py", refresh)
        if src:
            self.ssdp = literal_from_py(src, "SSDP") or {}
        src = fetch_source("integrations.json", refresh)
        if src:
            self._load_core(json.loads(src))
        self._load_hacs(refresh)
        self._load_oui(refresh)
        log(f"  Core-Integrationen: {len(self.core)}, DHCP-Regeln: {len(self.dhcp)}, "
            f"mDNS-Typen: {len(self.zeroconf)}, SSDP: {len(self.ssdp)}, "
            f"HACS: {len(self.hacs)}, MAC-Präfixe: {sum(len(v) for v in self.oui.values())}")

    def _load_core(self, data: dict) -> None:
        for dom, v in data.get("integration", {}).items():
            if "integrations" in v:
                for sub, sv in v["integrations"].items():
                    self.core[sub] = {"name": sv.get("name", sub),
                                      "config_flow": sv.get("config_flow", False),
                                      "iot_class": sv.get("iot_class", "")}
            else:
                self.core[dom] = {"name": v.get("name", dom),
                                  "config_flow": v.get("config_flow", False),
                                  "iot_class": v.get("iot_class", "")}

    def _load_hacs(self, refresh: bool) -> None:
        src = fetch_source("hacs_data.json", refresh)
        if src:
            try:
                data = json.loads(src)
                items = data.values() if isinstance(data, dict) else data
                for it in items:
                    fn = it.get("full_name") or ""
                    if not fn:
                        continue
                    self.hacs.append({
                        "full_name": fn,
                        "name": it.get("manifest_name") or it.get("name") or fn.split("/")[-1],
                        "description": it.get("description") or "",
                        "domain": it.get("domain") or "",
                        "stars": int(it.get("stargazers_count") or it.get("stars") or 0),
                        "topics": " ".join(it.get("topics") or []),
                    })
            except Exception as e:  # noqa: BLE001
                log(f"  ! HACS-Daten unlesbar: {e}")
        if not self.hacs:
            src = fetch_source("hacs_list.json", refresh)
            if src:
                for fn in json.loads(src):
                    self.hacs.append({"full_name": fn, "name": fn.split("/")[-1],
                                      "description": "", "domain": "", "stars": 0,
                                      "topics": ""})

    def _load_oui(self, refresh: bool) -> None:
        src = fetch_source("manuf", refresh)
        if src:
            for line in src.decode("utf-8", "replace").splitlines():
                if not line or line.startswith("#"):
                    continue
                cols = line.split("\t")
                if len(cols) < 2:
                    continue
                pref, bits = cols[0], 24
                if "/" in pref:
                    pref, b = pref.split("/")
                    bits = int(b)
                hexs = re.sub(r"[^0-9A-Fa-f]", "", pref).upper()
                name = (cols[2] if len(cols) > 2 and cols[2].strip() else cols[1]).strip()
                self.oui.setdefault(bits, {})[hexs[: bits // 4]] = name
            return
        src = fetch_source("oui.csv", refresh)
        if src:
            for row in csv.reader(io.StringIO(src.decode("utf-8", "replace"))):
                if len(row) >= 3 and re.fullmatch(r"[0-9A-F]{6}", row[1]):
                    self.oui.setdefault(24, {})[row[1]] = row[2]

    def vendor(self, mac: str) -> str:
        if not mac:
            return ""
        hexs = mac.replace(":", "")
        for bits in sorted(self.oui, reverse=True):
            v = self.oui[bits].get(hexs[: bits // 4])
            if v:
                return v
        if is_random_mac(mac):
            return "(zufällige MAC – meist Handy/Tablet/Laptop)"
        return ""

    def core_link(self, domain: str) -> tuple[str, str]:
        info = self.core.get(domain, {})
        docs = f"https://www.home-assistant.io/integrations/{domain}/"
        if info.get("config_flow"):
            return (f"https://my.home-assistant.io/redirect/config_flow_start/?domain={domain}", docs)
        return docs, ""

    def core_suggestion(self, domain: str, reason: str, conf: int) -> Suggestion | None:
        if domain not in self.core:
            return None
        url, extra = self.core_link(domain)
        return Suggestion("core", self.core[domain]["name"], domain, url, extra, reason, conf)

    def hacs_search(self, keywords: list[str], must_all: bool = False, limit: int = 3) -> list:
        kws = [k.lower() for k in keywords if k]
        if not kws:
            return []
        scored = []
        for it in self.hacs:
            name_hay = f"{it['full_name']} {it['name']} {it['domain']}".lower()
            desc_hay = f"{it['description']} {it['topics']}".lower()
            hits_name = sum(1 for k in kws if k in name_hay)
            hits_desc = sum(1 for k in kws if k in desc_hay and k not in name_hay)
            hits = hits_name + hits_desc
            if hits == 0 or (must_all and hits < len(kws)):
                continue
            if hits_name == 0 and hits_desc < len(kws):
                continue
            score = hits_name * 10 + hits_desc * 4 + min(it["stars"], 2000) / 200
            scored.append((score, it))
        scored.sort(key=lambda x: -x[0])
        out = []
        for _, it in scored[:limit]:
            owner, repo = it["full_name"].split("/", 1)
            out.append(Suggestion(
                "hacs", it["name"], it["domain"],
                "https://my.home-assistant.io/redirect/hacs_repository/?"
                + urllib.parse.urlencode({"owner": owner, "repository": repo,
                                          "category": "integration"}),
                f"https://github.com/{it['full_name']}",
                it["description"][:140], 40, stars=it["stars"]))
        return out


# --------------------------------------------------------------------------
# Abgleich
# --------------------------------------------------------------------------

def _fn(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(str(value).lower(), str(pattern).lower())


def vendor_keyword(vendor: str) -> str:
    if not vendor or vendor.startswith("("):
        return ""
    words = re.findall(r"[A-Za-z0-9!\-]+", vendor.lower())
    for w in words:
        w = w.strip("-")
        if w in VENDOR_ALIASES:
            return VENDOR_ALIASES[w]
        if w in VENDOR_SKIP_WORDS or len(w) < 3:
            continue
        if w in CHIP_VENDORS:
            return ""
        return w
    return ""


def match_host(h: Host, kb: Knowledge) -> None:
    sugg: list[Suggestion] = []

    def add(s: Suggestion | None):
        if s:
            sugg.append(s)

    mac_hex = h.mac.replace(":", "")
    short_host = h.hostname.split(".")[0].lower() if h.hostname else ""

    # 1) DHCP-Regeln (MAC-Präfix / Hostname)
    for rule in kb.dhcp:
        if "macaddress" not in rule and "hostname" not in rule:
            continue
        ok, why = True, []
        if "macaddress" in rule:
            ok &= bool(mac_hex) and _fn(mac_hex, rule["macaddress"])
            why.append("MAC-Präfix")
        if "hostname" in rule:
            ok &= bool(short_host) and _fn(short_host, rule["hostname"])
            why.append("Hostname")
        if ok:
            conf = 85 if len(why) == 2 else (75 if "MAC-Präfix" in why else 65)
            add(kb.core_suggestion(rule["domain"], "DHCP-Regel: " + " + ".join(why), conf))

    # 2) Zeroconf / mDNS
    for stype, entries in h.mdns.items():
        for rule in kb.zeroconf.get(stype, []):
            if isinstance(rule, str):
                rule = {"domain": rule}
            for e in entries:
                ok = True
                if "name" in rule:
                    ok &= _fn(e["name"], rule["name"])
                for pk, pv in (rule.get("properties") or {}).items():
                    ok &= pk.lower() in e["props"] and _fn(e["props"][pk.lower()], pv)
                if ok:
                    add(kb.core_suggestion(rule["domain"], f"mDNS {stype}", 90))
                    break
        if stype == "_hap._tcp.local.":
            for e in entries:
                model = e["props"].get("md", "")
                for key, v in kb.homekit.items():
                    if model.startswith(key):
                        add(kb.core_suggestion(v["domain"], f"HomeKit-Modell {model}", 90))
                add(kb.core_suggestion("homekit_controller", "bietet HomeKit (HAP) an", 55))

    # 3) SSDP
    for dom, rules in kb.ssdp.items():
        for rule in rules:
            for s in h.ssdp:
                if all(_fn(s.get(k, ""), v) for k, v in rule.items()):
                    add(kb.core_suggestion(dom, "UPnP/SSDP-Kennung", 85))
                    break

    # 4) Ports & HTTP-Fingerprints
    ports = set(h.ports)
    all_titles = " ".join(v.get("title", "") for v in h.http.values()).lower()
    all_server = " ".join(v.get("server", "") for v in h.http.values()).lower()
    all_body = " ".join(v.get("body_hint", "") for v in h.http.values())
    probes = {}
    for v in h.http.values():
        probes.update(v.get("probes", {}))
    vk = vendor_keyword(h.vendor)

    if 8123 in ports:
        h.notes.append("Home Assistant läuft auf diesem Gerät")
    if 6053 in ports:
        add(kb.core_suggestion("esphome", "ESPHome-API-Port 6053 offen", 90))
    if 1883 in ports or 8883 in ports:
        add(kb.core_suggestion("mqtt", "MQTT-Broker auf diesem Gerät", 70))
        h.notes.append("MQTT-Broker gefunden: Geräte wie Tasmota/Zigbee2MQTT verbinden sich hierhin")
    if 8009 in ports or 8008 in ports:
        add(kb.core_suggestion("cast", "Google-Cast-Port offen", 70))
    if 1400 in ports:
        add(kb.core_suggestion("sonos", "Sonos-Port 1400 offen", 70))
    if "/shelly" in probes and isinstance(probes["/shelly"], dict):
        add(kb.core_suggestion("shelly", "Antwortet auf /shelly", 95))
    wi = probes.get("/json/info")
    if isinstance(wi, dict) and str(wi.get("brand", "")).lower() == "wled":
        add(kb.core_suggestion("wled", "WLED-JSON-API", 95))
    if "/solar_api/GetAPIVersion.cgi" in probes:
        add(kb.core_suggestion("fronius", "Fronius Solar API", 95))
    if "tasmota" in all_titles or "tasmota" in all_body:
        add(kb.core_suggestion("tasmota", "Tasmota-Weboberfläche (MQTT im Gerät aktivieren)", 90))
    if "fritz!box" in all_titles or "fritz!" in all_server:
        add(kb.core_suggestion("fritz", "FRITZ!Box-Weboberfläche", 90))
    if "esphome" in all_titles or "esphome" in all_body[:2000]:
        add(kb.core_suggestion("esphome", "ESPHome-Weboberfläche", 80))
    for key, kws in (("opendtu", ["opendtu"]), ("ahoydtu", ["ahoy"]),
                     ("openbeken", ["openbeken"]), ("evcc", ["evcc"]),
                     ("zigbee2mqtt", ["zigbee2mqtt"]), ("go-echarger", ["go-e"])):
        if key in all_titles.replace(" ", "") or key in all_body[:3000]:
            hits = kb.hacs_search(kws, limit=2)
            for s in hits:
                s.reason, s.confidence = f"Weboberfläche „{key}“ erkannt", 75
                add(s)
            if not hits:
                q = urllib.parse.quote_plus(f"{kws[0]} home assistant")
                add(Suggestion("github", f"GitHub-Suche „{kws[0]} home assistant“", "",
                               f"https://github.com/search?q={q}&type=repositories&s=stars",
                               reason=f"Weboberfläche „{key}“ erkannt – oft per MQTT-Discovery einbindbar",
                               confidence=50))
                if 1883 not in ports:
                    h.notes.append(f"{key}: meist über MQTT (mit HA-Auto-Discovery) einbindbar")
            if key == "zigbee2mqtt":
                add(kb.core_suggestion("mqtt", "Zigbee2MQTT gefunden – Einbindung via MQTT", 80))
    if 6668 in ports:
        add(kb.core_suggestion("tuya", "Tuya-Port 6668 offen (Cloud-Integration)", 60))
        local = [x for x in kb.hacs_search(["local", "tuya"], must_all=True, limit=6)
                 if not re.search(r"\bir\b|_rc\b|remote|\bir[_ ]", f"{x.title} {x.url}".lower())]
        for s in local[:2]:
            s.reason, s.confidence = "Tuya-Port 6668 offen (lokale Steuerung)", 70
            add(s)
    if 502 in ports:
        h.notes.append("Modbus TCP offen – Registerbelegung aus Herstellerdoku/Integration nötig")
        found = []
        if vk:
            found = kb.hacs_search([vk, "modbus"], must_all=True, limit=2) or \
                kb.hacs_search([vk, "solar"], must_all=True, limit=2)
        for s in found:
            s.reason, s.confidence = f"Modbus TCP + Hersteller „{vk}“", 70
            add(s)
        add(kb.core_suggestion("modbus", "Modbus TCP (Port 502) – generisch per YAML", 45))
    if 554 in ports:
        add(kb.core_suggestion("onvif", "RTSP-Port offen – Kamera? (ONVIF probieren)", 40))
        add(kb.core_suggestion("generic", "RTSP-Stream als generische Kamera", 35))

    # 5) Herstellername -> Core/HACS/GitHub (schwache Treffer, nur als Ergänzung)
    strong = any(s.confidence >= 65 for s in sugg)
    if vk:
        if not strong:
            for dom, info in kb.core.items():
                n = info["name"].lower()
                if dom.startswith(("emulated", "homekit")):
                    continue
                if re.search(rf"\b{re.escape(vk)}", n) or dom.startswith(vk.replace("-", "")):
                    add(kb.core_suggestion(dom, f"Name passt zu Hersteller „{vk}“", 35))
            if 502 not in ports:
                for s in kb.hacs_search([vk], limit=3):
                    s.reason = f"HACS-Treffer für Hersteller „{vk}“"
                    s.confidence = 30
                    add(s)
        if not any(s.kind == "github" for s in sugg) and not any(s.confidence >= 80 for s in sugg):
            q = urllib.parse.quote_plus(f"{vk} home assistant")
            add(Suggestion("github", f"GitHub-Suche „{vk} home assistant“", "",
                           f"https://github.com/search?q={q}&type=repositories&s=stars",
                           reason="Fallback", confidence=10))
    elif h.vendor and not h.vendor.startswith("(") and not strong:
        h.notes.append(f"MAC gehört zu Chip-Hersteller „{h.vendor.split(',')[0]}“ – "
                       "typisch für ESPHome/Tasmota/Tuya-Geräte, Weboberfläche prüfen")

    # Duplikate zusammenfassen (höchste Sicherheit gewinnt)
    best: dict = {}
    for s in sugg:
        key = (s.kind, s.domain or s.url)
        if key not in best or s.confidence > best[key].confidence:
            if key in best and best[key].reason not in s.reason:
                s.reason = f"{s.reason}; {best[key].reason}"
            best[key] = s
        elif best[key].reason and s.reason not in best[key].reason:
            best[key].reason += f"; {s.reason}"
    h.suggestions = sorted(best.values(), key=lambda s: (-s.confidence, -s.stars))


# --------------------------------------------------------------------------
# Home Assistant: bereits eingerichtete Integrationen
# --------------------------------------------------------------------------

def ha_loaded_components(url: str, token: str) -> set:
    token = token.strip().strip('"').strip("'")
    log(f"  Token: {len(token)} Zeichen, {token.count('.') + 1} Teile "
        f"(erwartet: ca. 180 Zeichen, 3 Teile)")
    try:
        data = json.loads(http_get(url.rstrip("/") + "/api/config", timeout=10,
                                   headers={"Authorization": f"Bearer {token}"}, lan=True))
    except urllib.error.HTTPError as e:
        hint = {401: "Token ungültig oder unvollständig kopiert – neuen Token erstellen",
                403: "Zugriff verweigert – IP evtl. von HA gesperrt (ip_ban)"}.get(e.code, "")
        log(f"  ! Home Assistant antwortet mit HTTP {e.code} – {hint or e.reason}")
        return set()
    except Exception as e:  # noqa: BLE001
        log(f"  ! Home Assistant nicht erreichbar ({e}) – Abgleich übersprungen")
        return set()
    comps = set()
    for c in data.get("components", []):
        comps.update(c.split("."))
    log(f"  {len(comps)} geladene Komponenten in Home Assistant gefunden")
    return comps


def hacs_domains_installed(comps: set, kb: Knowledge) -> None:
    for it in kb.hacs:
        it["installed"] = bool(it["domain"]) and it["domain"] in comps


# Cloud-Integrationen, für die es lokale Alternativen gibt:
# Core-Domain -> (Anzeigename, Suchbegriffe für lokale HACS-Varianten)
CLOUD_WITH_LOCAL = {
    "tuya": ("Tuya-Cloud", ("tuya",)),
}


def apply_installed(h: Host, comps: set, ip_entries: dict | None = None,
                    kb: "Knowledge | None" = None) -> None:
    """Markiert eingerichtete Integrationen und stuft Alternativen zu Upgrades herab.

    ip_entries: IP -> [(domain, Titel)] aus den Config-Entries von Home Assistant
    (nur in der HA-Integration verfügbar) – damit ist die Zuordnung exakt.
    """
    for s in h.suggestions:
        if s.domain and s.domain in comps:
            s.installed = True
    for domain, title in (ip_entries or {}).get(h.ip, []):
        hit = next((s for s in h.suggestions if s.domain == domain), None)
        if hit:
            hit.installed, hit.confidence = True, 99
            hit.reason = f"eingerichtet als „{title}“"
        else:
            name = kb.core[domain]["name"] if kb and domain in kb.core else domain
            h.suggestions.append(Suggestion(
                "core" if kb and domain in kb.core else "hacs", name, domain,
                f"https://my.home-assistant.io/redirect/integration/?domain={domain}",
                reason=f"eingerichtet als „{title}“", confidence=99, installed=True))
    for dom, (label, kws) in CLOUD_WITH_LOCAL.items():
        cloud = next((s for s in h.suggestions if s.kind == "core" and s.domain == dom), None)
        if not cloud or not cloud.installed:
            continue
        cloud.title = f"über {label} eingebunden"
        cloud.reason = f"{cloud.reason} – Steuerung läuft über die Cloud"
        cloud.confidence = max(cloud.confidence, 90)
        for s in h.suggestions:
            if s.kind == "hacs" and not s.installed and \
                    any(k in f"{s.title} {s.url}".lower() for k in kws):
                s.upgrade = True
                s.confidence = min(s.confidence, 50)
                s.reason = "Optionales Upgrade: lokale Steuerung ohne Internet (Local Key nötig)"
    h.suggestions.sort(key=lambda s: (not s.installed, s.kind == "github", s.upgrade,
                                      -s.confidence, -s.stars))


# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------

KIND_LABEL = {"core": "Core", "hacs": "HACS", "github": "GitHub", "info": "Info"}


def conf_label(c: int) -> str:
    return "hoch" if c >= 80 else "mittel" if c >= 55 else "niedrig" if c >= 30 else "Suche"


def write_html(hosts: list, path: str, subnet: str, meta: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(hosts, subnet, meta))


def render_html(hosts: list, subnet: str, meta: dict) -> str:
    e = html.escape
    rows = []
    n_open = n_done = n_upg = 0
    for h in hosts:
        sug_html = []
        top = [s for s in h.suggestions if s.kind != "github"][:5]
        gh = [s for s in h.suggestions if s.kind == "github"]
        has_open = not any(s.installed for s in top) and \
            any(not s.upgrade and s.confidence >= 55 for s in top)
        has_done = any(s.installed for s in top)
        n_open += has_open
        n_done += has_done
        n_upg += any(s.upgrade for s in top)
        if any(s.installed for s in top):
            gh = []  # schon eingebunden – keine Suche nötig
        for s in top + gh:
            stars = f" ★{s.stars}" if s.stars else ""
            status = "<span class='ok'>✓ eingerichtet</span>" if s.installed else \
                "<span class='upg'>optional</span>" if s.upgrade else ""
            extra = f" · <a href='{e(s.extra_url)}' target='_blank'>{'Doku' if s.kind == 'core' else 'GitHub'}</a>" if s.extra_url else ""
            action = "Hinzufügen" if s.kind == "core" and "config_flow_start" in s.url else \
                "In HACS öffnen" if s.kind == "hacs" else "Öffnen"
            url = s.url
            if s.installed and s.domain:
                action = "In HA öffnen"
                url = f"https://my.home-assistant.io/redirect/integration/?domain={s.domain}"
            sug_html.append(
                f"<div class='sug {e(s.kind)} c{conf_label(s.confidence)}{' up' if s.upgrade else ''}'>"
                f"<span class='tag'>{KIND_LABEL[s.kind]}</span> "
                f"<b>{e(s.title)}</b>{e(stars)} {status}"
                f"<span class='conf'>{'' if s.installed or s.upgrade else conf_label(s.confidence)}</span><br>"
                f"<a href='{e(url)}' target='_blank'>{action}</a>{extra}"
                f"<div class='why'>{e(s.reason)}</div></div>")
        notes = "".join(f"<div class='note'>ℹ {e(n)}</div>" for n in h.notes)
        protos = "".join(f"<span class='pill'>{e(p)}</span>" for p in h.protocols)
        titles = "; ".join(f"{p}: {v['title']}" for p, v in h.http.items() if v.get("title"))
        rows.append(
            f"<tr data-open='{int(has_open)}'>"
            f"<td class='mono'><a href='http://{e(h.ip)}' target='_blank'>{e(h.ip)}</a></td>"
            f"<td><b>{e(h.display_name) or '–'}</b>"
            f"<div class='sub'>{e(h.hostname)}</div><div class='sub'>{e(titles)}</div></td>"
            f"<td><span class='mono'>{e(h.mac) or '–'}</span><div class='sub'>{e(h.vendor)}</div></td>"
            f"<td>{protos or '<span class=sub>keine offenen Ports</span>'}</td>"
            f"<td>{''.join(sug_html) or '<span class=sub>kein Vorschlag</span>'}{notes}</td></tr>")

    doc = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netzwerk-Inventar {e(subnet)}</title>
<style>
:root{{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--mut:#6b6b66;--line:#e3e2dc;--core:#1f6feb;--hacs:#2da44e;--gh:#6e7781;--ok:#1a7f37}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161615;--card:#1f1f1e;--fg:#ecebe6;--mut:#9d9c96;--line:#33332f;--core:#58a6ff;--hacs:#3fb950;--gh:#8b949e;--ok:#3fb950}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}
header{{padding:20px 16px 8px;max-width:1400px;margin:auto}}h1{{font-size:20px;margin:0 0 4px}}
.meta{{color:var(--mut)}}.bar{{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:12px 0}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}}
.stat b{{font-size:18px;display:block}}#q{{padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);min-width:220px}}
.wrap{{max-width:1400px;margin:auto;padding:0 16px 40px;overflow-x:auto}}
table{{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:8px}}
th,td{{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}}
th{{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);position:sticky;top:0;background:var(--card)}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}}.sub{{color:var(--mut);font-size:12px}}
.pill{{display:inline-block;border:1px solid var(--line);border-radius:10px;padding:1px 7px;margin:1px 3px 2px 0;font-size:12px;white-space:nowrap}}
.sug{{border-left:3px solid var(--gh);padding:3px 8px;margin:0 0 6px}}.sug.core{{border-color:var(--core)}}.sug.hacs{{border-color:var(--hacs)}}
.sug.cniedrig,.sug.cSuche{{opacity:.75}}.tag{{font-size:11px;font-weight:600;color:var(--mut)}}
.conf{{float:right;font-size:11px;color:var(--mut)}}.why{{color:var(--mut);font-size:12px}}.ok{{color:var(--ok);font-weight:600}}.upg{{font-size:11px;border:1px solid var(--line);border-radius:8px;padding:0 6px;color:var(--mut)}}.sug.up{{opacity:.8;border-left-style:dashed}}
.note{{font-size:12px;color:var(--mut);margin-top:4px}}a{{color:var(--core)}}
label{{color:var(--mut)}}
</style></head><body>
<header><h1>Netzwerk-Inventar {e(subnet)}</h1>
<div class="meta">Scan vom {e(meta['time'])} · Dauer {meta['duration']:.0f} s · Datenbasis: {meta['core']} Core-Integrationen, {meta['hacs']} HACS-Repos{' · Abgleich mit deinem Home Assistant aktiv' if meta['ha'] else ' · ohne Abgleich mit Home Assistant (--ha-url/HA_TOKEN)'}{' · ' + e(meta['source']) if meta.get('source') else ''}</div>
<div class="bar"><div class="stat"><b>{len(hosts)}</b>Geräte</div>
<div class="stat"><b>{n_open}</b>mit offenem Vorschlag</div>
<div class="stat"><b>{n_done}</b>bereits eingebunden</div>
<div class="stat"><b>{n_upg}</b>mit optionalem Upgrade</div>
<input id="q" placeholder="Filtern (IP, Name, Hersteller …)">
<label><input type="checkbox" id="only"> nur Geräte mit offenem Vorschlag</label></div></header>
<div class="wrap"><table><thead><tr><th>IP</th><th>Gerät</th><th>MAC / Hersteller</th><th>Protokolle</th><th>Vorschläge</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="sub">„Hinzufügen“-Links öffnen über my.home-assistant.io direkt deinen Home Assistant. „In HACS öffnen“ setzt voraus, dass HACS installiert ist.
Sicherheit: hoch = eindeutige Kennung (mDNS/DHCP/API), mittel = Port/Weboberfläche, niedrig = nur Herstellername.</p></div>
<script>
const q=document.getElementById('q'),o=document.getElementById('only');
function f(){{const t=q.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{{
r.style.display=(r.textContent.toLowerCase().includes(t)&&(!o.checked||r.dataset.open==='1'))?'':'none'}})}}
q.oninput=f;o.onchange=f;
</script></body></html>"""
    return doc


def print_table(hosts: list) -> None:
    print(f"\n{'IP':<16}{'Gerät':<28}{'Hersteller':<24}Vorschlag")
    print("-" * 100)
    for h in hosts:
        top = next((s for s in h.suggestions if s.kind != "github"), None)
        sug = "–"
        if top:
            sug = f"{KIND_LABEL[top.kind]}: {top.title}" + (" ✓" if top.installed else "")
            if any(s.upgrade for s in h.suggestions):
                sug += " (lokal möglich)"
        print(f"{h.ip:<16}{(h.display_name or '–')[:27]:<28}{(h.vendor or '–')[:23]:<24}{sug}")


# --------------------------------------------------------------------------
# Scan-Ablauf (von Skript und HA-Integration gemeinsam genutzt)
# --------------------------------------------------------------------------

def scan_network(subnet: str, kb: "Knowledge", timeout: float = 0.8,
                 workers: int = 128, http: bool = True) -> list:
    net = ipaddress.ip_network(subnet, strict=False)
    ips = [str(i) for i in net.hosts()]

    hosts: dict[str, Host] = {}
    log(f"Portscan {net} ({len(ips)} Adressen × {len(PORTS)} Ports) …")
    port_scan(hosts, ips, timeout, workers)

    log("mDNS-Abfrage …")
    for ip, svcs in mdns_scan().items():
        if ip in ips:
            h = hosts.setdefault(ip, Host(ip))
            h.alive, h.mdns = True, svcs
    log("SSDP/UPnP-Abfrage …")
    for ip, entries in ssdp_scan().items():
        if ip in ips:
            h = hosts.setdefault(ip, Host(ip))
            h.alive, h.ssdp = True, entries

    arp = read_arp_table()
    log(f"  ARP-Tabelle: {sum(1 for ip in arp if ip in ips)} MAC-Adressen im Subnetz")
    for ip, mac in arp.items():
        if ip in ips:
            h = hosts.setdefault(ip, Host(ip))
            h.alive, h.mac = True, mac
    if not arp:
        log("  ! ARP-Tabelle leer – MAC-Adressen/Hersteller fehlen "
            "(Skript im selben Netz ausführen, nicht über VPN)")

    alive = [h for h in hosts.values() if h.alive]
    log(f"{len(alive)} aktive Geräte – Namen & Web-Oberflächen …")
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        names = dict(zip([h.ip for h in alive], ex.map(reverse_dns, [h.ip for h in alive])))
        jobs = {}
        if http:
            for h in alive:
                for p in HTTP_PORTS:
                    if p in h.ports:
                        jobs[ex.submit(http_fingerprint, h.ip, p)] = (h, p)
        for fut in cf.as_completed(jobs):
            h, p = jobs[fut]
            h.http[p] = fut.result()
    for h in alive:
        h.hostname = names.get(h.ip, "")
        h.vendor = kb.vendor(h.mac)

    alive.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return alive


def evaluate(hosts: list, kb: "Knowledge", comps: set,
             ip_entries: dict | None = None) -> None:
    for h in hosts:
        match_host(h, kb)
        apply_installed(h, comps, ip_entries, kb)


def summary(hosts: list) -> dict:
    """Kennzahlen – gleiche Logik wie im HTML-Bericht."""
    out = {"devices": len(hosts), "open": 0, "done": 0, "upgrade": 0, "open_list": []}
    for h in hosts:
        top = [s for s in h.suggestions if s.kind != "github"][:5]
        done = any(s.installed for s in top)
        is_open = not done and any(not s.upgrade and s.confidence >= 55 for s in top)
        out["done"] += done
        out["upgrade"] += any(s.upgrade for s in top)
        if is_open:
            out["open"] += 1
            best = next(s for s in top if not s.upgrade and s.confidence >= 55)
            out["open_list"].append({"ip": h.ip, "name": h.display_name, "vendor": h.vendor,
                                     "suggestion": best.title, "kind": best.kind,
                                     "url": best.url})
    return out


# --------------------------------------------------------------------------
# Hauptprogramm
# --------------------------------------------------------------------------

def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="Netzwerk scannen und passende Home-Assistant-Integrationen vorschlagen")
    ap.add_argument("--subnet", default=DEFAULT_SUBNET, help=f"z. B. {DEFAULT_SUBNET}")
    ap.add_argument("--ha-url", default=os.environ.get("HA_URL", ""),
                    help="z. B. http://192.168.50.10:8123 (für Abgleich mit eingerichteten Integrationen)")
    ap.add_argument("--ha-token", default=os.environ.get("HA_TOKEN", ""),
                    help="Long-Lived Access Token (besser per Umgebungsvariable HA_TOKEN)")
    ap.add_argument("--out", default="ha_netscan_report.html", help="HTML-Bericht")
    ap.add_argument("--json", default="", help="zusätzlich Rohdaten als JSON speichern")
    ap.add_argument("--timeout", type=float, default=0.8, help="Port-Timeout in Sekunden")
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--refresh", action="store_true", help="Datenquellen neu laden")
    ap.add_argument("--no-http", action="store_true", help="keine Web-Oberflächen abfragen")
    args = ap.parse_args()

    t0 = time.time()
    kb = Knowledge(refresh=args.refresh)
    alive = scan_network(args.subnet, kb, args.timeout, args.workers, not args.no_http)
    net = ipaddress.ip_network(args.subnet, strict=False)

    comps: set = set()
    if args.ha_url and args.ha_token:
        log("Abgleich mit Home Assistant …")
        comps = ha_loaded_components(args.ha_url, args.ha_token)

    evaluate(alive, kb, comps)
    meta = {"time": time.strftime("%d.%m.%Y %H:%M"), "duration": time.time() - t0,
            "core": len(kb.core), "hacs": len(kb.hacs), "ha": bool(comps)}
    write_html(alive, args.out, str(net), meta)
    print_table(alive)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([{**{k: v for k, v in h.__dict__.items() if k != "suggestions"},
                        "http": {p: {k: v for k, v in d.items() if k != "body_hint"}
                                 for p, d in h.http.items()},
                        "suggestions": [s.__dict__ for s in h.suggestions]} for h in alive],
                      fh, ensure_ascii=False, indent=1, default=str)
    log(f"\nFertig in {time.time() - t0:.0f} s. Bericht: {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("Abgebrochen.")
        sys.exit(130)
