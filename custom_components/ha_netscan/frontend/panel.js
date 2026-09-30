// Netzwerk-Inventar – Seitenleisten-Panel für Home Assistant
// Holt den Bericht über die authentifizierte API (/api/ha_netscan/report)
// und zeigt ihn in einem abgeschotteten iframe (sandbox) an.

const esc = (t) => String(t).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

class HaNetscanPanel extends HTMLElement {
  constructor() {
    super();
    this._hass = null;
    this._narrow = false;
    this._timer = null;
    this._lastHtml = null;
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = `
      <style>
        :host { display:flex; flex-direction:column; height:100%;
                background: var(--primary-background-color); color: var(--primary-text-color);
                font-family: var(--paper-font-body1_-_font-family, system-ui, sans-serif); }
        header { display:flex; align-items:center; gap:12px; height:56px; padding:0 12px 0 4px;
                 background: var(--app-header-background-color, var(--primary-color));
                 color: var(--app-header-text-color, #fff); flex:0 0 auto; }
        h1 { font-size:20px; font-weight:400; margin:0; flex:1; white-space:nowrap;
             overflow:hidden; text-overflow:ellipsis; }
        #status { font-size:13px; opacity:.9; white-space:nowrap; }
        button { background: rgba(255,255,255,.15); color: inherit; border:1px solid rgba(255,255,255,.4);
                 border-radius:18px; padding:7px 14px; font-size:14px; cursor:pointer; }
        button:disabled { opacity:.5; cursor:default; }
        .spin { display:inline-block; width:12px; height:12px; border:2px solid currentColor;
                border-right-color:transparent; border-radius:50%; animation:r 1s linear infinite;
                vertical-align:-2px; margin-right:6px; }
        @keyframes r { to { transform:rotate(360deg) } }
        iframe { flex:1 1 auto; border:0; width:100%; background: var(--primary-background-color); }
        .empty { padding:40px 20px; text-align:center; color: var(--secondary-text-color); }
        .err { color: var(--error-color, #db4437); }
        @media (max-width: 600px) { #status { display:none } }
      </style>
      <header>
        <ha-menu-button></ha-menu-button>
        <h1>Netzwerk-Inventar</h1>
        <span id="status"></span>
        <button id="scan">Jetzt scannen</button>
      </header>
      <div id="body" class="empty">Lade …</div>`;
    this.shadowRoot.getElementById("scan").addEventListener("click", () => this._scan());
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    const mb = this.shadowRoot.querySelector("ha-menu-button");
    if (mb) { mb.hass = hass; mb.narrow = this._narrow; }
    if (first) this._load();
  }
  set narrow(v) {
    this._narrow = v;
    const mb = this.shadowRoot.querySelector("ha-menu-button");
    if (mb) mb.narrow = v;
  }
  set panel(_p) {}

  disconnectedCallback() { clearTimeout(this._timer); }
  connectedCallback() { if (this._hass) this._load(); }

  async _scan() {
    try {
      await this._hass.callApi("POST", "ha_netscan/report");
    } catch (e) { /* Status zeigt Fehler */ }
    setTimeout(() => this._load(), 500);
  }

  async _load() {
    clearTimeout(this._timer);
    let d;
    try {
      d = await this._hass.callApi("GET", "ha_netscan/report");
    } catch (e) {
      this._status(`<span class="err">Fehler: ${esc(e.message || e.body?.message || e)}</span>`, false);
      this._timer = setTimeout(() => this._load(), 15000);
      return;
    }
    const last = d.last_scan ? new Date(d.last_scan).toLocaleString() : "noch nie";
    if (d.scanning) {
      this._status(`<span class="spin"></span>Scan läuft (${esc(d.subnet)}) …`, true);
    } else if (d.error) {
      this._status(`<span class="err">Letzter Scan fehlgeschlagen</span>`, false);
    } else {
      const s = d.summary || {};
      this._status(`${s.devices ?? 0} Geräte · ${s.open ?? 0} offen · letzter Scan ${last}`, false);
    }
    const body = this.shadowRoot.getElementById("body");
    if (d.html && d.html !== this._lastHtml) {
      this._lastHtml = d.html;
      const f = document.createElement("iframe");
      // Keine same-origin-Rechte: der Bericht kann nicht auf Home Assistant zugreifen
      f.setAttribute("sandbox", "allow-scripts allow-popups allow-popups-to-escape-sandbox");
      f.srcdoc = d.html;
      body.replaceWith(f);
      f.id = "body";
    } else if (!d.html) {
      body.className = "empty";
      body.innerHTML = d.scanning
        ? "Der erste Scan läuft – das dauert etwa eine Minute …"
        : (d.error ? `<span class="err">${esc(d.error)}</span>` : "Noch kein Scan vorhanden. Klicke auf „Jetzt scannen“.");
    }
    this._timer = setTimeout(() => this._load(), d.scanning ? 3000 : 60000);
  }

  _status(html, busy) {
    this.shadowRoot.getElementById("status").innerHTML = html;
    this.shadowRoot.getElementById("scan").disabled = busy;
  }
}

customElements.define("ha-netscan-panel", HaNetscanPanel);
