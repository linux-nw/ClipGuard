# ClipGuard

Redacts secrets in the Windows clipboard before you paste them anywhere. Windows 10/11, Windows PowerShell 5.1.

ClipGuard runs in the tray, checks every copied text and replaces detected secrets with `[REDACTED]`.
No matter where you paste afterwards (AI chat, forum, ticket, Teams): the secret is already gone.
The original stays in the Windows clipboard history (`Win+V`) and can be restored deliberately.

---

## Detection

1. **Fixed formats**: around 180 own rules (Azure/Entra/SharePoint, GitHub, AI providers, home server services, hashes, key files ...)
2. **Keyword + value**: `password=...`, `"client_secret": "..."`, `--token ...`, `<Password>...</Password>`, cookies, headers
3. **Entropy**: long random strings without a known format
4. **Remembered secrets**: every detected secret (and everything a password manager copies) is kept in RAM until exit and is then also redacted in variations: upper/lower case, URL-encoded, Base64, Hex, JSON/XML/shell-escaped, line-wrapped, as a fragment
5. **gitleaks rules** (optional): the maintained rules from [gitleaks](https://github.com/gitleaks/gitleaks) can be downloaded

Encoded content (Base64, Hex, gzip, URL encoding, Unicode escapes ...) is decoded before checking.

---

## Usage

Requirements: Windows 10 or 11, Windows PowerShell 5.1 (preinstalled).

| Action | Command |
| --- | --- |
| Start (tray) | Double-click `ClipGuard.cmd` |
| Self-test | `ClipGuard.cmd -SelbstTest` |
| Check a file (shows the redacted version) | `ClipGuard.cmd -Pruefe .\datei.txt` |
| Autostart on / off | `ClipGuard.cmd -Autostart An` or `-Autostart Aus` |
| Load gitleaks rules | `ClipGuard.cmd -RegelnAktualisieren` |

Alternatively run it directly: `powershell -ExecutionPolicy Bypass -File .\clipguard.ps1 <parameters>`.

In the tray:

- **Left click on the shield**: 5 minute pause (grey shield), click again to switch it back on
- **Originale anzeigen** (show originals): the last 10 originals (RAM only), in case `Win+V` is off or blocked
- **Status-Fenster** (status window): history, remember a secret, forget remembered secrets, reload rules, update gitleaks, autostart

Own rules go into `clipguard-eigene.txt` (next to the script), one rule per line:

```
literal:interner-servername.firma.local
regex:\bKD-[A-Z]{2}\d{6}\b
```

Do not write real passwords into this file, it is plain text. For a single secret without a recognizable format,
copy it and use **Merken** (remember) in the status window instead.

Limits:

- Images, screenshots and copied files are not checked
- A single password without a format (e.g. `Sommer2026!`) is not detected on first copy
- Copies from password managers (Bitwarden, KeePass ...) are never changed, only remembered

---

## Repository structure

- `clipguard.ps1`: the program (detection engine, command line modes, tray)
- `ClipGuard.cmd`: launcher
- `clipguard-eigene.txt`: template for own rules
- `LICENSE`

---

## Privacy

- Log and settings are in `%LOCALAPPDATA%\ClipGuard`
- The log contains only rule names, never contents
- Remembered secrets and originals exist only in RAM and are gone after exit
- The only network access is the optional gitleaks rules download

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE). Private and non-commercial use is allowed. For commercial use, please get in touch.