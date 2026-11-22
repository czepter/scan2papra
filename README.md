# scan2papra

Scannt von einem Netzwerkscanner (getestet für den Epson ES-C320W) und lädt das PDF über die API in Papra hoch. Ohne SANE und ohne Hersteller-Treiber.

Auslöser:
- **Scan-Taste am Gerät** über WSD-Push. Der Container meldet sich beim Scanner als Scan-Ziel an, der Scanner meldet den Tastendruck zurück.
- `POST /scan` (Home Assistant, NFC, Shortcut) per eSCL
- Web-UI unter `http://<host>:8080/?token=…`
- optional `AUTO_SCAN`: startet, sobald Papier eingelegt ist

## Installation (Dockge / Docker Compose)

1. `docker-compose.yml` als neuen Stack in Dockge einfügen.
2. Die Variablen aus `.env.example` im Env-Bereich des Stacks eintragen.
3. Deploy.

Das Image `ghcr.io/czepter/scan2papra:latest` gibt es für amd64 und arm64.

## Vorab am Scanner prüfen (aus dem LAN)

```bash
curl -k https://<scanner-ip>/eSCL/ScannerCapabilities   # XML? -> /scan funktioniert
curl -k https://<scanner-ip>/eSCL/ScannerStatus         # AdfState? -> AUTO_SCAN möglich
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/soap+xml' \
  http://<scanner-ip>:80/WSD/DEVICE                       # Antwort != 000 -> WSD erreichbar
```

In der Web-Config des Scanners muss WSD aktiviert sein.

## Netzwerk

- Der Container muss den Scanner erreichen, läuft also im selben Netz.
- Der Scanner muss `WSD_PORT` (Standard 6666) auf dem Docker-Host erreichen. `WSD_CALLBACK_URL` nutzt die LAN-IP dieses Hosts. Keinen Reverse-Proxy-Hostnamen verwenden, der Scanner spricht nur HTTP.
- Dem Scanner im Router eine feste IP geben.

## Papra

API-Key mit `documents:create` anlegen, für Tags zusätzlich `tags:read` und `documents:update`.
Die Org-ID steht in der URL (`/organizations/<id>`).

## Erster Test der Taste

1. Stack starten. Im Log sollte stehen: `Als Scan-Ziel 'Papra' registriert, warte auf Scan-Taste`
2. Papier einlegen, Taste drücken.
3. Erwartet: `Scan-Taste gedrückt` → `WSD-Scanjob … gestartet` → `Hochgeladen: …`

Kommt bei Schritt 3 nichts, sendet der Scanner beim Tastendruck kein WSD-Ereignis. Dann `AUTO_SCAN=true` oder einen Taster mit `POST /scan` nehmen.
Kommt das Ereignis, aber `CreateScanJob abgelehnt`: `LOG_LEVEL=DEBUG` setzen und das Log ansehen.

## Bildverarbeitung

- `SKIP_BLANK`: leere Seiten (z. B. Rückseiten beim Duplex) fallen raus
- `AUTO_COLOR`: Seiten ohne Farbe werden als Graustufen gespeichert, das spart Platz
- `AUTO_CROP`: schneidet dunklen Einzugshintergrund unter kurzen oder schmalen Belegen (Kassenbons) ab
- `ROTATE=auto`: dreht jede Seite per Texterkennung (tesseract) richtig herum, auch bei gemischt eingelegten Stapeln. Feste Werte `0`, `90`, `180`, `270` überspringen die Erkennung
- Eine Schräglagenkorrektur gibt es nicht

## Endpunkte

| Methode | Pfad | |
|---|---|---|
| POST | `/scan` | Scan per eSCL starten. Optional `?duplex=false`, `?color=Grayscale8`, `?dpi=200` |
| GET | `/status` | Status, letztes Ergebnis, ADF-Zustand, WSD-Verbindung und letzter Tastendruck |
| POST | `/retry` | fehlgeschlagene Uploads erneut senden (läuft sonst alle 5 min automatisch) |
| GET | `/?token=…` | Web-UI fürs Handy |
| GET | `/health` | ohne Auth |

Auth: `Authorization: Bearer <TRIGGER_TOKEN>` oder `?token=`.

## Home Assistant

```yaml
rest_command:
  scan_to_papra:
    url: "http://<docker-host-ip>:8080/scan"
    method: POST
    headers:
      Authorization: !secret scan2papra_bearer   # "Bearer <token>"
```

## Image bauen

Actions → „Image bauen“ → Run workflow. Das Image landet unter `ghcr.io/czepter/scan2papra` mit den Tags `latest`, Commit-SHA und optional einer Version.
