# ClipGuard

Schwärzt Secrets in der Windows-Zwischenablage, bevor du sie irgendwo einfügst.

ClipGuard läuft im Tray, prüft jeden kopierten Text und ersetzt erkannte Secrets durch `[REDACTED]`.
Egal wohin du danach einfügst (KI-Chat, Forum, Ticket, Teams): das Secret ist schon raus.
Das Original bleibt im Windows-Zwischenablageverlauf (`Win+V`) und kann bewusst zurückgeholt werden.

## Erkennung

1. **Feste Formate**: rund 180 eigene Regeln (Azure/Entra/SharePoint, GitHub, KI-Anbieter, Homeserver-Dienste, Hashes, Schlüsseldateien ...)
2. **Stichwort + Wert**: `password=...`, `"client_secret": "..."`, `--token ...`, `<Password>...</Password>`, Cookies, Header
3. **Entropie**: lange Zufallsstrings ohne bekanntes Format
4. **Gemerkte Secrets**: jedes erkannte Secret (und alles, was ein Passwortmanager kopiert) wird bis zum Beenden im RAM gehalten und danach auch in Variationen geschwärzt: Groß/Klein, URL-kodiert, Base64, Hex, JSON-/XML-/Shell-escaped, umgebrochen, als Bruchstück
5. **gitleaks-Regeln** (optional): die gepflegten Regeln aus [gitleaks](https://github.com/gitleaks/gitleaks) lassen sich nachladen

Kodierte Inhalte (Base64, Hex, gzip, URL-Encoding, Unicode-Escapes ...) werden vor der Prüfung entpackt.

## Voraussetzungen

- Windows 10 oder 11
- Windows PowerShell 5.1 (ist vorinstalliert)

## Benutzung

| Aktion | Befehl |
| --- | --- |
| Starten (Tray) | Doppelklick auf `ClipGuard.cmd` |
| Selbsttest | `ClipGuard.cmd -SelbstTest` |
| Datei prüfen (zeigt geschwärzte Version) | `ClipGuard.cmd -Pruefe .\datei.txt` |
| Autostart an / aus | `ClipGuard.cmd -Autostart An` bzw. `-Autostart Aus` |
| gitleaks-Regeln laden | `ClipGuard.cmd -RegelnAktualisieren` |

Alternativ direkt: `powershell -ExecutionPolicy Bypass -File .\clipguard.ps1 <Parameter>`.

Im Tray:

- **Linksklick aufs Schild**: 5 Minuten Pause (graues Schild), erneut klicken schaltet wieder ein
- **Originale anzeigen**: die letzten 10 Originale (nur im RAM), falls `Win+V` aus oder gesperrt ist
- **Status-Fenster**: Verlauf, Secret merken, Gemerktes vergessen, Regeln neu laden, gitleaks aktualisieren, Autostart

## Eigene Regeln

In `clipguard-eigene.txt` (neben dem Skript), eine Regel pro Zeile:

```
literal:interner-servername.firma.local
regex:\bKD-[A-Z]{2}\d{6}\b
```

Keine echten Passwörter in diese Datei schreiben, sie ist Klartext. Für ein einzelnes Secret ohne erkennbares Format
lieber: kopieren, dann im Status-Fenster **Merken**.

## Daten

- Protokoll und Einstellungen liegen in `%LOCALAPPDATA%\ClipGuard`
- Das Protokoll enthält nur Regelnamen, nie Inhalte
- Gemerkte Secrets und Originale existieren nur im RAM und sind nach dem Beenden weg

## Grenzen

- Bilder, Screenshots und kopierte Dateien werden nicht geprüft
- Ein einzelnes Passwort ohne Format (z. B. `Sommer2026!`) wird beim ersten Kopieren nicht erkannt
- Kopien aus Passwortmanagern (Bitwarden, KeePass ...) werden nie verändert, nur gemerkt

## Lizenz

[MIT](LICENSE)
