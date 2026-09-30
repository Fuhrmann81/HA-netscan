# Netzwerk-Inventar für Home Assistant

Scannt dein Heimnetz, erkennt Geräte und Protokolle und schlägt passende
Integrationen vor – aus Home Assistant Core, HACS oder per GitHub-Suche.
Bereits eingerichtete Integrationen werden erkannt und markiert.

## Funktionen

- Eigener Menüpunkt **Netzwerk-Inventar** in der Seitenleiste (nur für Admins)
  mit Knopf **Jetzt scannen**
- Erkennung über offene Ports, ARP/MAC-Hersteller, mDNS, UPnP/SSDP und
  Web-Oberflächen (Shelly, WLED, Tasmota, Fronius, OpenDTU …)
- Abgleich mit den Discovery-Regeln von Home Assistant (DHCP, Zeroconf, SSDP)
  und der HACS-Liste
- Exakte Zuordnung, wenn eine Integration die IP-Adresse eines Geräts kennt
  („eingerichtet als …“)
- Cloud-Integrationen mit lokaler Alternative (z. B. Tuya → LocalTuya)
  werden als **optionales Upgrade** gezeigt
- Filter per Klick auf die Kacheln: offene Vorschläge, verfügbare Upgrades,
  eingebunden, ohne Zuordnung – plus Freitextsuche
- Sensoren: Geräte im Netz, Offene Vorschläge (mit Geräteliste als Attribut),
  Eingebunden, Optionale Upgrades, Letzter Scan
- Automatischer Scan in einstellbarem Intervall (Standard 24 h, 0 = nur manuell)

Modbus-Register werden bewusst **nicht** abgefragt – es wird nur geprüft,
ob Port 502 offen ist.

## Installation (manuell)

1. Den Ordner `custom_components/ha_netscan` nach
   `/config/custom_components/ha_netscan` kopieren
   (z. B. mit dem Add-on *Samba share* oder *Studio Code Server*).
2. Home Assistant neu starten.
3. *Einstellungen → Geräte & Dienste → Integration hinzufügen →
   „Netzwerk-Inventar“*. Das Subnetz wird automatisch vorgeschlagen.

## Installation über HACS (benutzerdefiniertes Repository)

HACS → ⋮ → *Benutzerdefinierte Repositories* → URL dieses Repositories,
Kategorie *Integration*.

## Datenquellen

Beim ersten Scan werden geladen und 7 Tage zwischengespeichert
(`/config/.storage/ha_netscan_cache`):

- Home Assistant Core: `generated/dhcp.py`, `zeroconf.py`, `ssdp.py`, `integrations.json`
- HACS: `data-v2.hacs.xyz` (Fallback: Liste aus `hacs/default`)
- MAC-Hersteller: Wireshark `manuf` (Fallback: IEEE `oui.csv`)

## Eigenständiges Skript

`netscan.py` läuft auch ohne Home Assistant (Python 3.9+, keine Abhängigkeiten):

```
python netscan.py                          # eigenes Netz wird automatisch erkannt
python netscan.py --subnet 192.168.1.0/24  # oder Netz selbst angeben
```

## Lizenz

MIT
