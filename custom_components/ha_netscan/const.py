"""Konstanten für Netzwerk-Inventar."""

DOMAIN = "ha_netscan"
NAME = "Netzwerk-Inventar"

CONF_SUBNET = "subnet"
CONF_INTERVAL = "scan_interval_hours"
DEFAULT_INTERVAL = 24  # Stunden, 0 = nur manuell
MIN_PREFIX = 22  # größtes erlaubtes Netz: /22 (1022 Adressen)

PANEL_URL = "netzwerk-inventar"
PANEL_ELEMENT = "ha-netscan-panel"
STATIC_URL = "/ha_netscan_static"
API_URL = "/api/ha_netscan/report"

# Schlüssel in Config-Entries, unter denen Integrationen typischerweise die IP speichern
HOST_KEYS = ("host", "ip_address", "ip", "address", "url", "base_url", "hostname")
