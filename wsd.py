"""WSD-Push-Empfänger: meldet sich beim Scanner als Scan-Ziel an und reagiert auf die Scan-Taste.

Ablauf (WS-Scan):
  Probe -> Get (Metadaten, Scan-Service-Adresse) -> Subscribe(ScanAvailableEvent)
  Taste gedrückt -> Scanner POSTet ScanAvailableEvent an unseren Callback
  -> GetScannerElements (DefaultScanTicket) -> CreateScanJob -> RetrieveImage bis keine Seiten mehr
"""

import copy
import email
import socket
import io
import logging
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests
from PIL import Image

log = logging.getLogger("scan2papra.wsd")

NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "mex": "http://schemas.xmlsoap.org/ws/2004/09/mex",
    "wsdp": "http://schemas.xmlsoap.org/ws/2006/02/devprof",
    "wscn": "http://schemas.microsoft.com/windows/2006/08/wdp/scan",
}
for _p, _u in NS.items():
    ET.register_namespace(_p, _u)

SCAN_NS = NS["wscn"]
ANON = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
HEADERS = {"User-Agent": "WSDAPI", "Content-Type": "application/soap+xml"}


def q(tag: str) -> str:
    prefix, name = tag.split(":")
    return f"{{{NS[prefix]}}}{name}"


def find(el, path: str):
    return el.find(path, NS) if el is not None else None


def text(el, path: str, default: str = "") -> str:
    node = find(el, path)
    return (node.text or "").strip() if node is not None and node.text else default


def duration(seconds: int) -> str:
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"P0Y0M0DT{h}H{m}M{s}S"


class WSDFault(RuntimeError):
    def __init__(self, op: str, subcode: str, reason: str):
        super().__init__(f"{op}: {subcode} {reason}".strip())
        self.subcode = subcode


def envelope(to: str, action: str, from_urn: str, body: str = "", extra_header: str = "") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{NS['soap']}" xmlns:wsa="{NS['wsa']}" xmlns:wse="{NS['wse']}" xmlns:wsd="{NS['wsd']}" xmlns:wscn="{NS['wscn']}">
  <soap:Header>
    <wsa:To>{to}</wsa:To>
    <wsa:Action>{action}</wsa:Action>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>{ANON}</wsa:Address></wsa:ReplyTo>
    <wsa:From><wsa:Address>{from_urn}</wsa:Address></wsa:From>
    {extra_header}
  </soap:Header>
  <soap:Body>{body}</soap:Body>
</soap:Envelope>"""


class WSDClient:
    def __init__(self, target: str, callback_url: str, on_images, *, display_name="Papra",
                 ep_ref: str = "", ttl: int = 900, renew_every: int = 600,
                 color: str = "RGB24", dpi: int = 300, duplex: bool = True):
        self.target = target
        self.callback_url = callback_url
        self.on_images = on_images  # callable(fetch_fn) -> startet die Verarbeitung
        self.display_name = display_name
        self.ep_ref = ep_ref
        self.ttl = ttl
        self.renew_every = renew_every
        self.color = color
        self.dpi = dpi
        self.duplex = duplex
        self.from_urn = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, callback_url)}"
        self.context = "scan2papra"
        self.service_addr = ""
        self.sub_manager = ""
        self.sub_id = ""
        self.dest_token = ""
        self.connected = False
        self.last_event = None

    # ------------------------------------------------------------ SOAP

    def post(self, addr: str, msg: str, op: str, timeout: int = 60) -> ET.Element:
        r = requests.post(addr, data=msg.encode(), headers=HEADERS, timeout=timeout)
        if not r.content:
            r.raise_for_status()
            raise RuntimeError(f"{op}: leere Antwort (HTTP {r.status_code})")
        x = ET.fromstring(r.content)
        fault = find(x, ".//soap:Fault")
        if fault is not None:
            raise WSDFault(op, text(fault, ".//soap:Subcode/soap:Value"), text(fault, ".//soap:Reason/soap:Text"))
        return x

    # ------------------------------------------------------------ Verbindung

    def udp_probe(self, timeout: float = 4.0) -> tuple[str, str]:
        """WS-Discovery-Probe per UDP direkt an den Scanner (Port 3702). Liefert (EndpointReference, XAddr)."""
        host = urlparse(self.target).hostname
        msg = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{NS['soap']}" xmlns:wsa="{NS['wsa']}" xmlns:wsd="{NS['wsd']}">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>{NS['wsd']}/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body><wsd:Probe/></soap:Body>
</soap:Envelope>""".encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            deadline = time.time() + timeout
            sent = 0
            while time.time() < deadline:
                if sent < 3:
                    sock.sendto(msg, (host, 3702))
                    sent += 1
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    x = ET.fromstring(data)
                except ET.ParseError:
                    continue
                for match in x.iterfind(".//wsd:ProbeMatch", NS):
                    ep = text(match, "wsa:EndpointReference/wsa:Address")
                    xaddrs = text(match, "wsd:XAddrs").split()
                    xaddr = next((a for a in xaddrs if a.startswith("http://") and host in a), "") \
                        or next((a for a in xaddrs if a.startswith("http")), "")
                    if ep:
                        return ep, xaddr
        finally:
            sock.close()
        raise RuntimeError(f"keine WS-Discovery-Antwort von {host}:3702 (WSD im Scanner aktiviert?)")

    def discover(self):
        ep_ref = self.ep_ref
        if not ep_ref:
            ep_ref, xaddr = self.udp_probe()
            log.info("WS-Discovery: %s via %s", ep_ref, xaddr or self.target)
            if xaddr:
                self.target = xaddr

        msg = envelope(ep_ref, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get", self.from_urn)
        x = self.post(self.target, msg, "Get")
        model = text(x, ".//wsdp:ModelName", "?")
        for hosted in x.iterfind(".//wsdp:Hosted", NS):
            if "ScannerServiceType" in text(hosted, "wsdp:Types"):
                self.service_addr = text(hosted, ".//wsa:EndpointReference/wsa:Address")
                break
        if not self.service_addr:
            raise RuntimeError("Gerät bietet keinen WSD-Scan-Service an")
        log.info("WSD-Gerät: %s, Scan-Service: %s", model, self.service_addr)

    def subscribe(self):
        body = f"""<wse:Subscribe>
      <wse:Delivery><wse:NotifyTo><wsa:Address>{self.callback_url}</wsa:Address></wse:NotifyTo></wse:Delivery>
      <wse:Expires>{duration(self.ttl)}</wse:Expires>
      <wse:Filter Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Action">{SCAN_NS}/ScanAvailableEvent</wse:Filter>
      <wscn:ScanDestinations><wscn:ScanDestination>
        <wscn:ClientDisplayName>{self.display_name}</wscn:ClientDisplayName>
        <wscn:ClientContext>{self.context}</wscn:ClientContext>
      </wscn:ScanDestination></wscn:ScanDestinations>
    </wse:Subscribe>"""
        x = self.post(self.service_addr, envelope(self.service_addr, f"{NS['wse']}/Subscribe", self.from_urn, body),
                      "Subscribe")
        self.sub_id = text(x, ".//wse:Identifier")
        self.sub_manager = text(x, ".//wse:SubscriptionManager/wsa:Address") or self.service_addr
        self.dest_token = text(x, ".//wscn:DestinationToken")
        if not self.dest_token:
            raise RuntimeError("Subscribe ohne DestinationToken – Gerät unterstützt evtl. keine Push-Scans")
        log.info("Als Scan-Ziel '%s' registriert, warte auf Scan-Taste", self.display_name)

    def renew(self):
        header = f"<wse:Identifier>{self.sub_id}</wse:Identifier>"
        body = f"<wse:Renew><wse:Expires>{duration(self.ttl)}</wse:Expires></wse:Renew>"
        self.post(self.sub_manager, envelope(self.sub_manager, f"{NS['wse']}/Renew", self.from_urn, body, header),
                  "Renew")

    def unsubscribe(self):
        if not self.sub_id:
            return
        try:
            header = f"<wse:Identifier>{self.sub_id}</wse:Identifier>"
            self.post(self.sub_manager, envelope(self.sub_manager, f"{NS['wse']}/Unsubscribe", self.from_urn,
                                                 "<wse:Unsubscribe/>", header), "Unsubscribe", timeout=5)
            log.info("WSD-Abo beendet")
        except Exception as e:
            log.debug("Unsubscribe fehlgeschlagen: %s", e)

    def run_forever(self):
        delay = 10
        while True:
            try:
                self.connected = False
                self.discover()
                self.subscribe()
                self.connected = True
                delay = 10
                while True:
                    time.sleep(self.renew_every)
                    self.renew()
                    log.debug("WSD-Abo erneuert")
            except Exception as e:
                self.connected = False
                log.warning("WSD-Verbindung fehlgeschlagen: %s – neuer Versuch in %ds", e, delay)
                time.sleep(delay)
                delay = min(delay * 2, 300)

    # ------------------------------------------------------------ Scan

    def build_ticket(self, use_defaults_only: bool) -> str:
        body = f"""<wscn:GetScannerElementsRequest><wscn:RequestedElements>
      <wscn:Name>wscn:ScannerConfiguration</wscn:Name><wscn:Name>wscn:DefaultScanTicket</wscn:Name>
    </wscn:RequestedElements></wscn:GetScannerElementsRequest>"""
        x = self.post(self.service_addr, envelope(self.service_addr, f"{SCAN_NS}/GetScannerElements",
                                                  self.from_urn, body), "GetScannerElements")
        default = find(x, ".//wscn:DefaultScanTicket")
        if default is None:
            raise RuntimeError("Scanner liefert kein DefaultScanTicket")
        ticket = ET.Element(q("wscn:ScanTicket"))
        for child in default:
            ticket.append(copy.deepcopy(child))
        if use_defaults_only:
            return ET.tostring(ticket, encoding="unicode")

        config = find(x, ".//wscn:ScannerConfiguration")
        formats = {(f.text or "").strip() for f in config.iterfind(".//wscn:FormatValue", NS)} if config is not None else set()
        has_duplex = config is not None and find(config, ".//wscn:ADF/wscn:ADFSupportsDuplex") is not None \
            and text(config, ".//wscn:ADF/wscn:ADFSupportsDuplex") in ("true", "1")

        params = find(ticket, "wscn:DocumentParameters")
        if params is None:
            return ET.tostring(ticket, encoding="unicode")

        def set_value(path: str, value: str):
            node = find(params, path)
            if node is not None:
                node.text = value

        if "jfif" in formats:
            set_value("wscn:Format", "jfif")
        set_value("wscn:ImagesToTransfer", "0")
        use_duplex = self.duplex and has_duplex
        set_value("wscn:InputSource", "ADFDuplex" if use_duplex else "ADF")
        sides = find(params, "wscn:MediaSides")
        front = find(sides, "wscn:MediaFront")
        if front is not None:
            set_value("wscn:MediaSides/wscn:MediaFront/wscn:ColorProcessing", self.color)
            set_value("wscn:MediaSides/wscn:MediaFront/wscn:Resolution/wscn:Width", str(self.dpi))
            set_value("wscn:MediaSides/wscn:MediaFront/wscn:Resolution/wscn:Height", str(self.dpi))
            back = find(sides, "wscn:MediaBack")
            if use_duplex and back is None:
                back = copy.deepcopy(front)
                back.tag = q("wscn:MediaBack")
                sides.append(back)
            elif not use_duplex and back is not None:
                sides.remove(back)
        return ET.tostring(ticket, encoding="unicode")

    def create_job(self, scan_id: str) -> tuple[str, str]:
        last_error = None
        for defaults_only in (False, True):
            try:
                ticket = self.build_ticket(defaults_only)
                body = f"""<wscn:CreateScanJobRequest>
      <wscn:ScanIdentifier>{scan_id}</wscn:ScanIdentifier>
      <wscn:DestinationToken>{self.dest_token}</wscn:DestinationToken>
      {ticket}
    </wscn:CreateScanJobRequest>"""
                x = self.post(self.service_addr, envelope(self.service_addr, f"{SCAN_NS}/CreateScanJob",
                                                          self.from_urn, body), "CreateScanJob")
                return text(x, ".//wscn:JobId"), text(x, ".//wscn:JobToken")
            except WSDFault as e:
                last_error = e
                if e.subcode.endswith("ClientErrorNoImagesAvailable"):
                    raise
                log.warning("CreateScanJob abgelehnt (%s)%s", e,
                            " – versuche Standard-Ticket" if not defaults_only else "")
        raise last_error

    def retrieve_image(self, job_id: str, job_token: str, n: int) -> bytes | None:
        body = f"""<wscn:RetrieveImageRequest>
      <wscn:JobId>{job_id}</wscn:JobId><wscn:JobToken>{job_token}</wscn:JobToken>
      <wscn:DocumentDescription><wscn:DocumentName>page{n}</wscn:DocumentName></wscn:DocumentDescription>
    </wscn:RetrieveImageRequest>"""
        r = requests.post(self.service_addr, data=envelope(self.service_addr, f"{SCAN_NS}/RetrieveImage",
                                                          self.from_urn, body).encode(),
                          headers=HEADERS, timeout=180)
        ctype = r.headers.get("Content-Type", "")
        if "multipart" not in ctype.lower():
            x = ET.fromstring(r.content)
            fault = find(x, ".//soap:Fault")
            if fault is not None and text(fault, ".//soap:Subcode/soap:Value").endswith("ClientErrorNoImagesAvailable"):
                return None
            if fault is not None:
                raise WSDFault("RetrieveImage", text(fault, ".//soap:Subcode/soap:Value"),
                               text(fault, ".//soap:Reason/soap:Text"))
            raise RuntimeError("RetrieveImage: Antwort ohne Bilddaten")

        msg = email.message_from_bytes(b"MIME-Version: 1.0\r\nContent-Type: " + ctype.encode() + b"\r\n\r\n" + r.content)
        for part in msg.walk():
            if part.is_multipart():
                continue
            ptype = part.get_content_type()
            if "xml" in ptype:
                continue
            data = part.get_payload(decode=True)
            if data:
                return to_jpeg(data)
        raise RuntimeError("RetrieveImage: kein Bildteil in der Antwort")

    def fetch_pages(self, scan_id: str) -> list[bytes]:
        try:
            job_id, job_token = self.create_job(scan_id)
        except WSDFault as e:
            if e.subcode.endswith("ClientErrorNoImagesAvailable"):
                return []
            raise
        log.info("WSD-Scanjob %s gestartet", job_id)
        pages = []
        while True:
            img = self.retrieve_image(job_id, job_token, len(pages))
            if img is None:
                break
            pages.append(img)
            log.info("Seite %d empfangen (%d KB)", len(pages), len(img) // 1024)
        return pages

    # ------------------------------------------------------------ Callback

    def handle_notification(self, raw: bytes):
        try:
            x = ET.fromstring(raw)
        except ET.ParseError:
            return
        action = text(x, ".//wsa:Action")
        if not action.endswith("/ScanAvailableEvent"):
            log.debug("WSD-Ereignis ignoriert: %s", action)
            return
        context = text(x, ".//wscn:ClientContext")
        scan_id = text(x, ".//wscn:ScanIdentifier")
        log.info("Scan-Taste gedrückt (Kontext %s)", context)
        self.last_event = time.strftime("%Y-%m-%dT%H:%M:%S")
        if context and context != self.context:
            log.info("Fremder Kontext, ignoriert")
            return
        self.on_images(lambda: self.fetch_pages(scan_id))

    def serve_callback(self, port: int):
        client = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log.debug(fmt, *args)

            def _body(self) -> bytes:
                length = self.headers.get("Content-Length")
                if length:
                    return self.rfile.read(int(length))
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    data = b""
                    while True:
                        size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                        if size == 0:
                            self.rfile.readline()
                            return data
                        data += self.rfile.read(size)
                        self.rfile.readline()
                return b""

            def do_POST(self):
                raw = self._body()
                self.send_response(202)
                self.send_header("Content-Type", "application/soap+xml")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                if raw:
                    threading.Thread(target=client.handle_notification, args=(raw,), daemon=True).start()

        log.info("WSD-Callback lauscht auf Port %d (%s)", port, self.callback_url)
        ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def to_jpeg(data: bytes) -> bytes:
    if data[:3] == b"\xff\xd8\xff":
        return data
    im = Image.open(io.BytesIO(data))
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    out = io.BytesIO()
    im.save(out, "JPEG", quality=90)
    return out.getvalue()
