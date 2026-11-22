"""scan2papra – scannt per eSCL (AirScan) vom Netzwerkscanner und lädt das PDF in Papra hoch.

Auslöser:
  - Scan-Taste am Gerät (WSD-Push, falls der Scanner das Ereignis sendet)
  - POST /scan            (Home Assistant, NFC-Tag, Shortcut, curl)
  - Web-UI unter /?token=…
  - optional AUTO_SCAN: startet, sobald Papier im Einzug liegt (eSCL AdfState)
"""

import datetime as dt
import io
import json
import logging
import os
import secrets
import signal
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import img2pdf
import requests
import urllib3
from PIL import Image

import wsd

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scan2papra")


def env(name: str, default: str | None = None, required: bool = False) -> str:
    val = os.getenv(name, default)
    if required and not val:
        raise SystemExit(f"Umgebungsvariable {name} fehlt")
    return val or ""


def env_bool(name: str, default: bool) -> bool:
    return env(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


SCANNER_URL = env("SCANNER_URL", required=True).rstrip("/")  # z. B. https://<scanner-ip>/eSCL
SCANNER_VERIFY_TLS = env_bool("SCANNER_VERIFY_TLS", False)  # Epson nutzt ein selbstsigniertes Zertifikat
PAPRA_URL = env("PAPRA_URL", required=True).rstrip("/")
PAPRA_API_KEY = env("PAPRA_API_KEY", required=True)
PAPRA_ORG_ID = env("PAPRA_ORG_ID", required=True)
PAPRA_TAG_IDS = [t.strip() for t in env("PAPRA_TAG_IDS", "").split(",") if t.strip()]
TRIGGER_TOKEN = env("TRIGGER_TOKEN", "")

DPI = int(env("DPI", "300"))
COLOR_MODE = env("COLOR_MODE", "RGB24")  # RGB24 | Grayscale8 | BlackAndWhite1
DUPLEX = env_bool("DUPLEX", True)
PAPER = env("PAPER", "A4").upper()
SKIP_BLANK = env_bool("SKIP_BLANK", True)
BLANK_RATIO = float(env("BLANK_RATIO", "0.004"))
FILENAME_PREFIX = env("FILENAME_PREFIX", "scan")

AUTO_SCAN = env_bool("AUTO_SCAN", False)
AUTO_SCAN_DELAY = float(env("AUTO_SCAN_DELAY", "3"))
POLL_INTERVAL = float(env("POLL_INTERVAL", "2"))

WSD_ENABLED = env_bool("WSD_ENABLED", True)
WSD_TARGET = env("WSD_TARGET", f"http://{urlparse(SCANNER_URL).hostname}:80/WSD/DEVICE")
WSD_CALLBACK_URL = env("WSD_CALLBACK_URL", "")  # z. B. http://<docker-host-ip>:6666/wsd
WSD_PORT = int(env("WSD_PORT", "6666"))
WSD_DISPLAY_NAME = env("WSD_DISPLAY_NAME", "Papra")
WSD_EP_REF = env("WSD_EP_REF", "")

DATA_DIR = Path(env("DATA_DIR", "/data"))
FAILED_DIR = DATA_DIR / "failed"
PORT = int(env("PORT", "8080"))

# Maße in 1/300 Zoll (eSCL ThreeHundredthsOfInches)
PAPER_SIZES = {"A4": (2480, 3508), "A5": (1748, 2480), "LETTER": (2550, 3300), "LEGAL": (2550, 4200)}
ESCL_NS = "http://schemas.hp.com/imaging/escl/2011/05/03"

SCAN_SETTINGS = """<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">
  <pwg:Version>2.6</pwg:Version>
  <scan:Intent>Document</scan:Intent>
  <pwg:ScanRegions>
    <pwg:ScanRegion>
      <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>
      <pwg:XOffset>0</pwg:XOffset>
      <pwg:YOffset>0</pwg:YOffset>
      <pwg:Width>{width}</pwg:Width>
      <pwg:Height>{height}</pwg:Height>
    </pwg:ScanRegion>
  </pwg:ScanRegions>
  <pwg:InputSource>Feeder</pwg:InputSource>
  <scan:Duplex>{duplex}</scan:Duplex>
  <scan:ColorMode>{color}</scan:ColorMode>
  <scan:XResolution>{dpi}</scan:XResolution>
  <scan:YResolution>{dpi}</scan:YResolution>
  <pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>
  <scan:DocumentFormatExt>image/jpeg</scan:DocumentFormatExt>
</scan:ScanSettings>"""

session = requests.Session()
session.verify = SCANNER_VERIFY_TLS
if not SCANNER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
wsd_client: "wsd.WSDClient | None" = None
scan_lock = threading.Lock()
state_lock = threading.Lock()
state: dict = {"state": "idle", "last": None}


def set_state(**kw):
    with state_lock:
        state.update(kw)


# ---------------------------------------------------------------- eSCL

def adf_loaded() -> bool | None:
    try:
        r = session.get(f"{SCANNER_URL}/ScannerStatus", timeout=10)
        r.raise_for_status()
        el = ET.fromstring(r.content).find(f".//{{{ESCL_NS}}}AdfState")
        return el is not None and (el.text or "").strip() == "ScannerAdfLoaded"
    except Exception as e:  # Scanner schläft / nicht erreichbar
        log.debug("ScannerStatus nicht abrufbar: %s", e)
        return None


def escl_scan(duplex: bool, color: str, dpi: int) -> list[bytes]:
    width, height = PAPER_SIZES.get(PAPER, PAPER_SIZES["A4"])
    body = SCAN_SETTINGS.format(width=width, height=height, duplex=str(duplex).lower(), color=color, dpi=dpi)

    for attempt in range(10):
        r = session.post(f"{SCANNER_URL}/ScanJobs", data=body.encode(),
                         headers={"Content-Type": "text/xml"}, timeout=30)
        if r.status_code != 503:
            break
        time.sleep(2)
    if r.status_code == 409:
        raise RuntimeError("Scanner meldet Konflikt (409) – kein Papier im Einzug?")
    r.raise_for_status()
    location = r.headers.get("Location")
    if not location:
        raise RuntimeError("Scanner hat keine Job-URL geliefert")
    job_url = urljoin(SCANNER_URL + "/", location).rstrip("/")
    log.info("Scanjob angelegt: %s", job_url)

    pages: list[bytes] = []
    busy = 0
    while True:
        p = session.get(f"{job_url}/NextDocument", timeout=180)
        if p.status_code == 200:
            pages.append(p.content)
            busy = 0
            log.info("Seite %d empfangen (%d KB)", len(pages), len(p.content) // 1024)
        elif p.status_code == 404:
            break
        elif p.status_code == 503 and busy < 60:
            busy += 1
            time.sleep(1)
        else:
            p.raise_for_status()
            break
    if not pages:
        raise RuntimeError("Keine Seiten gescannt – Papier eingelegt?")
    return pages


# ---------------------------------------------------------------- PDF

def is_blank(jpeg: bytes) -> bool:
    im = Image.open(io.BytesIO(jpeg)).convert("L")
    im.thumbnail((500, 500))
    w, h = im.size
    im = im.crop((int(w * 0.06), int(h * 0.06), int(w * 0.94), int(h * 0.94)))  # Ränder/Schatten ignorieren
    hist = im.histogram()
    dark = sum(hist[:190])
    return dark / max(sum(hist), 1) < BLANK_RATIO


def build_pdf(pages: list[bytes], dpi: int) -> tuple[bytes, int]:
    kept = pages
    if SKIP_BLANK:
        kept = [p for p in pages if not is_blank(p)] or pages
    layout = img2pdf.get_fixed_dpi_layout_fun((dpi, dpi))
    return img2pdf.convert(kept, layout_fun=layout), len(pages) - len(kept)


# ---------------------------------------------------------------- Papra

def papra_headers() -> dict:
    return {"Authorization": f"Bearer {PAPRA_API_KEY}"}


def upload_to_papra(pdf: bytes, filename: str) -> str:
    base = f"{PAPRA_URL}/api/organizations/{PAPRA_ORG_ID}/documents"
    r = requests.post(base, headers=papra_headers(),
                      files={"file": (filename, pdf, "application/pdf")}, timeout=180)
    r.raise_for_status()
    doc_id = (r.json().get("document") or {}).get("id", "")
    for tag in PAPRA_TAG_IDS:
        if not doc_id:
            break
        t = requests.post(f"{base}/{doc_id}/tags", headers=papra_headers(), json={"tagId": tag}, timeout=30)
        if not t.ok:
            log.warning("Tag %s konnte nicht gesetzt werden: %s %s", tag, t.status_code, t.text[:200])
    return doc_id


def retry_failed():
    for f in sorted(FAILED_DIR.glob("*.pdf")):
        try:
            doc_id = upload_to_papra(f.read_bytes(), f.name)
            f.unlink()
            log.info("Nachgereicht: %s -> %s", f.name, doc_id)
        except Exception as e:
            log.warning("Nachreichen fehlgeschlagen (%s): %s", f.name, e)
            return


# ---------------------------------------------------------------- Ablauf

def run_scan(source: str, duplex: bool, color: str, dpi: int, fetch=None):
    if not scan_lock.acquire(blocking=False):
        log.warning("Scan läuft bereits – Auslöser '%s' ignoriert", source)
        return
    started = time.time()
    try:
        set_state(state="scanning")
        log.info("Scan gestartet (%s, duplex=%s, %s, %d dpi)", source, duplex, color, dpi)
        pages = fetch() if fetch else escl_scan(duplex, color, dpi)
        if not pages:
            raise RuntimeError("Keine Seiten gescannt – Papier eingelegt?")
        pdf, skipped = build_pdf(pages, dpi)
        name = f"{FILENAME_PREFIX}-{dt.datetime.now():%Y-%m-%d_%H-%M-%S}.pdf"
        set_state(state="uploading")
        try:
            doc_id = upload_to_papra(pdf, name)
            result = {"ok": True, "document_id": doc_id}
            log.info("Hochgeladen: %s (%d Seiten, %d leer entfernt) -> %s", name, len(pages), skipped, doc_id)
        except Exception as e:
            FAILED_DIR.mkdir(parents=True, exist_ok=True)
            (FAILED_DIR / name).write_bytes(pdf)
            result = {"ok": False, "error": f"Upload fehlgeschlagen, zwischengespeichert: {e}"}
            log.error(result["error"])
        result.update(file=name, pages=len(pages), blank_removed=skipped)
    except Exception as e:
        log.exception("Scan fehlgeschlagen")
        result = {"ok": False, "error": str(e)}
    finally:
        scan_lock.release()
    result.update(source=source, finished=dt.datetime.now().isoformat(timespec="seconds"),
                  seconds=round(time.time() - started, 1))
    set_state(state="idle", last=result)


def start_scan(source: str, duplex=None, color=None, dpi=None) -> bool:
    if scan_lock.locked():
        return False
    threading.Thread(target=run_scan, daemon=True, args=(
        source,
        DUPLEX if duplex is None else duplex,
        color or COLOR_MODE,
        dpi or DPI,
    )).start()
    return True


def on_wsd_button(fetch):
    threading.Thread(target=run_scan, daemon=True, args=("taste", DUPLEX, COLOR_MODE, DPI, fetch)).start()


def auto_scan_loop():
    log.info("AUTO_SCAN aktiv (Poll %.1fs, Verzögerung %.1fs)", POLL_INTERVAL, AUTO_SCAN_DELAY)
    prev = True  # beim Start liegendes Papier nicht sofort scannen
    while True:
        loaded = adf_loaded()
        if loaded and not prev and not scan_lock.locked():
            time.sleep(AUTO_SCAN_DELAY)  # Stapel fertig einlegen lassen
            if adf_loaded():
                run_scan("auto", DUPLEX, COLOR_MODE, DPI)
                loaded = adf_loaded()
        if loaded is not None:
            prev = loaded
        time.sleep(POLL_INTERVAL)


def retry_loop():
    while True:
        retry_failed()
        time.sleep(300)


# ---------------------------------------------------------------- HTTP

UI = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan → Papra</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:40px auto;padding:0 16px;color:#222}
button{width:100%;padding:22px;font-size:1.3rem;border:0;border-radius:12px;background:#222;color:#fff;margin:6px 0}
button.alt{background:#e5e5e5;color:#222;font-size:1rem;padding:14px}
button:disabled{opacity:.4}
pre{background:#f4f4f4;padding:12px;border-radius:8px;white-space:pre-wrap;font-size:.85rem}
</style></head><body>
<h1>Scan → Papra</h1>
<button id="b" onclick="scan('')">Scannen</button>
<button class="alt" onclick="scan('duplex=false')">Nur Vorderseite</button>
<button class="alt" onclick="scan('color=Grayscale8')">Graustufen</button>
<p id="s">…</p><pre id="l"></pre>
<script>
const t=new URLSearchParams(location.search).get('token')||'';
const h={Authorization:'Bearer '+t};
async function scan(q){await fetch('/scan?'+q,{method:'POST',headers:h});poll()}
async function poll(){
 const r=await fetch('/status',{headers:h}); if(!r.ok){s.textContent='Nicht autorisiert';return}
 const j=await r.json(); s.textContent='Status: '+j.state; b.disabled=j.state!=='idle';
 l.textContent=j.last?JSON.stringify(j.last,null,2):'';
}
poll();setInterval(poll,2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _authorized(self, qs) -> bool:
        if not TRIGGER_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else (qs.get("token") or [""])[0]
        return secrets.compare_digest(token, TRIGGER_TOKEN)

    def _send(self, code: int, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if url.path == "/health":
            return self._send(200, {"ok": True})
        if not self._authorized(qs):
            return self._send(401, {"error": "unauthorized"})
        if url.path == "/":
            return self._send(200, UI, "text/html; charset=utf-8")
        if url.path == "/status":
            with state_lock:
                body = dict(state)
            body["adf_loaded"] = adf_loaded()
            body["wsd"] = None if wsd_client is None else {
                "connected": wsd_client.connected, "last_button": wsd_client.last_event}
            body["failed_pending"] = len(list(FAILED_DIR.glob("*.pdf"))) if FAILED_DIR.exists() else 0
            return self._send(200, body)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if not self._authorized(qs):
            return self._send(401, {"error": "unauthorized"})
        if url.path == "/scan":
            duplex = qs.get("duplex", [None])[0]
            started = start_scan(
                "http",
                duplex=None if duplex is None else duplex.lower() in ("1", "true", "yes"),
                color=qs.get("color", [None])[0],
                dpi=int(qs["dpi"][0]) if "dpi" in qs else None,
            )
            return self._send(202 if started else 409, {"started": started})
        if url.path == "/retry":
            threading.Thread(target=retry_failed, daemon=True).start()
            return self._send(202, {"started": True})
        self._send(404, {"error": "not found"})


def main():
    FAILED_DIR.mkdir(parents=True, exist_ok=True)
    if not TRIGGER_TOKEN:
        log.warning("TRIGGER_TOKEN leer – Endpunkte sind ungeschützt")
    threading.Thread(target=retry_loop, daemon=True).start()
    if AUTO_SCAN:
        threading.Thread(target=auto_scan_loop, daemon=True).start()
    if WSD_ENABLED:
        if not WSD_CALLBACK_URL:
            log.warning("WSD_CALLBACK_URL fehlt – Scan-Taste deaktiviert")
        else:
            global wsd_client
            wsd_client = wsd.WSDClient(WSD_TARGET, WSD_CALLBACK_URL, on_wsd_button,
                                       display_name=WSD_DISPLAY_NAME, ep_ref=WSD_EP_REF,
                                       color=COLOR_MODE, dpi=DPI, duplex=DUPLEX)
            threading.Thread(target=wsd_client.serve_callback, args=(WSD_PORT,), daemon=True).start()
            threading.Thread(target=wsd_client.run_forever, daemon=True).start()
            signal.signal(signal.SIGTERM, lambda *_: (wsd_client.unsubscribe(), os._exit(0)))
    log.info("Scanner: %s | Papra: %s (Org %s) | Port %d", SCANNER_URL, PAPRA_URL, PAPRA_ORG_ID, PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
