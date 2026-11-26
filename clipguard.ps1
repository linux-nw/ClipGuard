<#
  ClipGuard - schwaerzt Secrets in der Zwischenablage, bevor du sie irgendwo einfuegst.

  Laeuft im Tray, prueft jeden kopierten Text und ersetzt erkannte Secrets durch [REDACTED].
  Egal wohin du danach einfuegst (KI-Chat, Forum, Ticket, Teams): das Secret ist schon raus.

  Erkennung in 5 Schichten:
   1. Feste Formate      ~180 eigene Regeln (Azure/Entra/SharePoint, GitHub, KI-Anbieter, Homeserver, Hashes ...)
   2. Stichwort + Wert   password=..., "client_secret": "...", --token ..., <Password>...</Password>, Cookies, Header
   3. Entropie           lange Zufallsstrings ohne bekanntes Format
   4. Gemerkte Secrets   jedes erkannte Secret (und alles, was dein Passwortmanager kopiert) wird bis zum Beenden im RAM
                         gemerkt und danach auch in Variationen geschwaerzt: gross/klein, URL-kodiert, Base64, Hex,
                         JSON-/XML-/Shell-escaped, umgebrochen, als Bruchstueck (erste/letzte 16 Zeichen)
   5. gitleaks-Regeln    optional: ueber das Tray-Menue laedst du die ~220 gepflegten gitleaks-Regeln nach

  So arbeitet es:
   Alles Erkannte wird sofort ersetzt - mitten im Text genauso wie als einzelner Wert (Strg+V liefert [REDACTED]).
   Das Original bleibt im Windows-Zwischenablageverlauf: Win+V, dort das Original waehlen, fertig.
   (Windows legt von jeder Kopie einen Verlaufseintrag an, auch vom Original, bevor ClipGuard es ersetzt.)
   Was du bewusst aus Win+V zurueckholst, laesst ClipGuard durch. Zusaetzlich liegen die letzten 10 Originale im
   Tray-Menue unter "Originale (nur im RAM)", falls Win+V aus oder per Richtlinie gesperrt ist.
   Passwortmanager-Kopien (Bitwarden, KeePass ...) fasst ClipGuard nie an, merkt sie sich aber.
   Pause: Linksklick aufs Schild = 5 Minuten aus (graues Schild), nochmal klicken = wieder an (gruenes Schild).

  Grenzen: Bilder/Screenshots und kopierte Dateien werden nicht geprueft. Ein einzelnes Passwort ohne erkennbares
  Format (z.B. "Sommer2026!") erkennt ClipGuard beim ersten Kopieren nicht - dafuer gibt es im Tray-Menue
  "Aktuelle Zwischenablage als Secret merken" (oder den Passwortmanager-Weg).

  Aufruf:
    Start (Tray):        ClipGuard.cmd (Doppelklick)
    Selbsttest:          powershell -ExecutionPolicy Bypass -File .\clipguard.ps1 -SelbstTest
    Datei pruefen:       ... -Pruefe .\datei.txt        (zeigt die geschwaerzte Version)
    Autostart an/aus:    ... -Autostart An | Aus
    gitleaks-Regeln:     ... -RegelnAktualisieren
#>
param(
    [switch]$SelbstTest,
    [string]$Pruefe = "",
    [ValidateSet("", "An", "Aus")]
    [string]$Autostart = "",
    [switch]$RegelnAktualisieren,
    [string]$GitleaksDatei = ""
)

$ErrorActionPreference = "Stop"
$script:Marke      = "[REDACTED]"
$script:DatenDir   = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "ClipGuard" } else { Join-Path ([IO.Path]::GetTempPath()) "ClipGuard" }
$script:GlPfad     = if ($GitleaksDatei) { $GitleaksDatei } else { Join-Path $script:DatenDir "gitleaks.toml" }
$script:EigenePfad = Join-Path $PSScriptRoot "clipguard-eigene.txt"
$script:GlUrl      = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
$script:MaxZeichen = 4000000
try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }

# =====================================================================================================
#  REGELN
#  Format:  Art ::: Name ::: Regex
#   F = festes Format, Treffer wird immer geschwaerzt
#   W = Wert wird vorher geprueft (kein Platzhalter, keine Variable, kein Code)
#   B = wie W, zusaetzlich: reine Buchstabenwoerter gelten nicht als Secret
#  Gibt es eine Gruppe (?<s>...), wird nur die geschwaerzt, sonst der ganze Treffer.
# =====================================================================================================
$RegelTabelle = @'
# ---------- Schluesseldateien ----------
F ::: Privater Schluessel (PEM) ::: -----BEGIN[A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END[A-Z ]*PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s\\]+)
F ::: PuTTY-Schluessel ::: PuTTY-User-Key-File-\d:[\s\S]*?Private-MAC: ?[0-9a-fA-F]+
F ::: age-Schluessel ::: AGE-SECRET-KEY-1[A-Z0-9]{58}
F ::: WireGuard-Schluessel ::: (?i)\b(?:PrivateKey|PresharedKey)\s*=\s*(?<s>[A-Za-z0-9+/]{43}=)
F ::: Kerberos-Ticket ::: \bdoI[A-Za-z0-9+/]{300,}={0,2}
F ::: DPAPI-Blob (SecureString/RDP) ::: (?i)\b01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-f]{64,}

# ---------- Tokens allgemein ----------
F ::: JWT ::: \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*
F ::: JWT (unsigniert/JWE) ::: \beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{0,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]+)?
F ::: Bearer-Token ::: (?i)\bBearer\s+(?<s>(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{16,})
F ::: Basic-Auth ::: (?i)\bBasic\s+(?<s>(?=[A-Za-z0-9+/]*[0-9+/])[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])
W ::: Authorization-Header ::: (?i)\b(?:Proxy-)?Authorization["']?\s*[:=]\s*["']?(?:(?:Bearer|Basic|Token|Negotiate|NTLM|Digest|SharedKey|SharedAccessSignature|ApiKey|Key)\s+)?(?<s>[^\s"',;]{8,})
W ::: URL mit Passwort ::: (?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@"']{1,64}:(?<s>[^\s@/"']{1,128})@
F ::: URL-Parameter ::: (?i)[?&](?:access_token|refresh_token|secret|client_secret|password|passwd|pwd|pass|id_token|token|auth|authkey|api_key|apikey|api-key|key|signature|code|tempauth|sharekey|X-Amz-Signature|X-Amz-Security-Token|X-Amz-Credential|X-Goog-Signature|X-Plex-Token|subscription-key|hmac|jwt|session|sid|secret|client_secret|password|pwd)=(?<s>[^&\s"'<>#]{16,})
F ::: OTP-Geheimnis ::: otpauth://[^\s"'<>]+
W ::: Cookie-Header ::: (?i)\b(?:Set-)?Cookie\s*:\s*(?<s>[^\r\n"']{8,})
F ::: Sitzungs-Cookie ::: (?i)\b(?:ESTSAUTH(?:PERSISTENT|LIGHT)?|FedAuth|rtFa|SPOIDCRL|SignInStateCookie|\.AspNet(?:Core)?\.[A-Za-z.]+|ASP\.NET_SessionId|JSESSIONID|PHPSESSID|connect\.sid|sessionid|session_id|nc_session_id|oc_sessionPassphrase|nc_token|authentik_session|immich_access_token|beszel_token|__Secure-[A-Za-z0-9_.-]+|__Host-[A-Za-z0-9_.-]+|user_session|_gh_sess|cf_clearance)=(?<s>[^;\s"']{8,})
W ::: API-Key-Header ::: (?i)\b(?:X-Api-Key|Api-Key|X-Auth-Token|X-Auth-Key|X-Emby-Token|X-MediaBrowser-Token|X-Riot-Token|X-Functions-Key|Ocp-Apim-Subscription-Key|X-Vault-Token|X-Gitlab-Token|X-N8N-Api-Key|PRIVATE-TOKEN|X-Amz-Security-Token|X-Plex-Token|X-Access-Token|X-Secret|X-Hub-Signature(?:-256)?|x-goog-api-key|anthropic-api-key|xi-api-key|X-Upload-Token|X-CSRF-Token|X-XSRF-Token|requesttoken|X-RequestDigest)["']?\s*[:=]\s*["']?(?<s>[^\s"',;]{8,})

# ---------- Microsoft / Azure / M365 ----------
F ::: Entra-Client-Secret ::: (?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~-])
F ::: Azure-Key (Signatur) ::: (?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}(?:JQQJ99|\+ASt|\+AEh|\+ASb|\+AMC|\+ARm|AzSe|AzFu|AzCa|ACDb|AIoT|ACR[A-D]|AZDO|AZEG|ABAc)[A-Za-z0-9+/]{2,}={0,2}
F ::: Azure-Storage-Key (88 Zeichen) ::: (?<![A-Za-z0-9+/])(?<!sha512-)[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])
F ::: Azure-Key (44 Zeichen, Kontext) ::: (?i)\b(?:AccountKey|SharedAccessKey|SharedSecretValue|PrimaryKey|SecondaryKey|AccessKey|EndpointKey|Key1|Key2)\s*[=:]\s*["']?(?<s>[A-Za-z0-9+/]{43,88}={0,2})
F ::: SAS-Signatur ::: (?i)\bsig=(?<s>[A-Za-z0-9%+/=_-]{20,})
F ::: SharedAccessSignature ::: (?i)\bSharedAccessSignature\s*(?:=|\s)\s*(?<s>(?:sr|sv|sig|se|skn)=[^\s"';]{20,})
F ::: Azure-DevOps-PAT (alt) ::: (?<![A-Za-z0-9])(?=[a-z2-7]{0,51}[2-7])(?=[a-z2-7]{0,51}[a-z])[a-z2-7]{52}(?![A-Za-z0-9])
F ::: Microsoft-Refresh-Token ::: \b[01]\.A[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{100,}(?:\.[A-Za-z0-9_-]+)*
F ::: Microsoft-Konto-Token ::: \bM\.[CR]\d{1,3}_[A-Za-z0-9.!*$_-]{50,}
F ::: Teams/Office-Webhook ::: (?i)https://[a-z0-9.-]*(?:webhook\.office\.com|outlook\.office(?:365)?\.com/webhook)[^\s"'<>]+
F ::: Power-Automate/Logic-Apps-Trigger ::: (?i)https://[a-z0-9.-]+(?:logic\.azure\.com|powerplatform\.com|azure-apim\.net|flow\.microsoft\.com)[^\s"'<>]*?[?&]sig=(?<s>[^&\s"'<>]+)
F ::: Azure-Function-Key ::: (?i)https://[a-z0-9-]+\.azurewebsites\.net/[^\s"'<>]*?[?&]code=(?<s>[^&\s"'<>]{20,})
F ::: SharePoint-TempAuth ::: (?i)[?&]tempauth=(?<s>[^&\s"'<>]+)
F ::: SharePoint-FormDigest ::: \b0x[0-9A-F]{64,},\d{1,2} [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d -0000
W ::: ConvertTo-SecureString ::: (?i)ConvertTo-SecureString\s+(?:-String\s+)?(?<q>["'])(?<s>[^"'\r\n]+)\k<q>
F ::: BitLocker-Wiederherstellungsschluessel ::: (?<![\d-])\d{6}(?:-\d{6}){7}(?![\d-])
F ::: 5x5-Schluessel (Nextcloud-App-Passwort/Produktkey) ::: (?<![A-Za-z0-9-])(?=[A-Za-z0-9-]*[A-Z0-9])[A-Za-z0-9]{5}(?:-[A-Za-z0-9]{5}){4}(?![A-Za-z0-9-])
W ::: WLAN-Schluessel (XML) ::: (?i)<keyMaterial>(?<s>[^<]+)</keyMaterial>
W ::: WLAN-Schluessel (netsh) ::: (?im)^\s*(?:Schl\S{1,2}sselinhalt|Key Content)\s*:\s*(?<s>\S.*?)\s*$
W ::: net user ::: (?i)\bnet\s+user\s+\S+\s+(?<s>[^\s/*]\S*)\s+/add
W ::: net use ::: (?i)\bnet\s+use\s+\S+\s+\\\\\S+\s+(?<s>[^\s/*]\S*)\s+/user:
W ::: cmdkey/Schalter ::: (?i)(?<=\s)/(?:pass(?:word)?|p(?:wd)?):(?<q>["']?)(?<s>[^\s"']{3,})\k<q>
B ::: App-Konfig (key/value) ::: (?i)\b(?:key|name)\s*=\s*"[^"]*(?:password|pwd|secret|token|apikey|api_key|accesskey|connectionstring)[^"]*"\s+value\s*=\s*"(?<s>[^"]{3,})"

# ---------- Code-Hosting / CI ----------
F ::: GitHub-Token ::: \bgh[pousr]_[A-Za-z0-9]{36,255}\b
F ::: GitHub-Token (fine-grained) ::: \bgithub_pat_[A-Za-z0-9_]{36,255}\b
F ::: GitLab-Token ::: \bgl(?:pat|dt|rt|ptt|cbt|ft|soat|imt|agent|oas|ffct)-[A-Za-z0-9_.-]{20,}
F ::: Bitbucket/Atlassian-Token ::: \bAT(?:ATT|BB|CTT)3?[A-Za-z0-9_=-]{24,}
F ::: npm-Token ::: \bnpm_[A-Za-z0-9]{36}\b
F ::: PyPI-Token ::: \bpypi-[A-Za-z0-9_-]{50,}
F ::: NuGet-Key ::: \boy2[a-z0-9]{43}\b
F ::: Docker-Token ::: \bdckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}
F ::: crates.io-Token ::: \bcio[A-Za-z0-9]{32}\b
F ::: RubyGems-Token ::: \brubygems_[a-f0-9]{48}\b
F ::: SonarQube-Token ::: \bsq[upa]_[a-f0-9]{40}\b
F ::: JFrog-Key ::: \bAKCp[A-Za-z0-9]{69}\b
F ::: CircleCI-Token ::: \bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b
F ::: Buildkite-Token ::: \bbkua_[a-f0-9]{40}\b
F ::: Docker-Auth (config.json) ::: "auth"\s*:\s*"(?<s>[A-Za-z0-9+/=]{16,})"
W ::: netrc ::: (?i)\blogin\s+\S+\s+password\s+(?<s>\S+)

# ---------- KI-Anbieter ----------
F ::: sk-Key (OpenAI/Anthropic/OpenRouter/DeepSeek) ::: \bsk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}
F ::: Google-API-Key (Gemini/Maps/Firebase) ::: \bAIza[0-9A-Za-z_-]{35}
F ::: Google-OAuth-Secret ::: \bGOCSPX-[A-Za-z0-9_-]{28}
F ::: Google-OAuth-Token ::: \bya29\.[0-9A-Za-z_-]{20,}
F ::: Google-Refresh-Token ::: \b1//0[0-9A-Za-z_-]{40,}
F ::: HuggingFace-Token ::: \bhf_[A-Za-z0-9]{30,}\b
F ::: Groq-Key ::: \bgsk_[A-Za-z0-9]{40,}\b
F ::: xAI-Key ::: \bxai-[A-Za-z0-9]{40,}\b
F ::: Replicate-Token ::: \br8_(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{30,}\b
F ::: Perplexity-Key ::: \bpplx-[A-Za-z0-9]{40,}\b
F ::: Tavily-Key ::: \btvly-[A-Za-z0-9_-]{20,}
F ::: LangSmith-Key ::: \blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b
F ::: ElevenLabs-Key ::: \bsk_[a-f0-9]{48}\b
F ::: Fireworks/Together/Cerebras-Key ::: \b(?:fw|csk|tgp_v1)_(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}
F ::: Weights&Biases/Pinecone-Key ::: \bpcsk_[A-Za-z0-9_]{40,}

# ---------- Cloud / SaaS ----------
F ::: AWS-Access-Key ::: \b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16,}
F ::: AWS-Secret (Kontext) ::: (?i)aws.{0,20}?(?:secret|sk).{0,20}?[=:]\s*["']?(?<s>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])
F ::: Stripe-Key ::: \b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}
F ::: Stripe-Webhook-Secret ::: \bwhsec_[A-Za-z0-9+/=]{24,}
F ::: Slack-Token ::: \bxox[abeoprs]-[A-Za-z0-9-]{10,}
F ::: Slack-App-Token ::: \bxapp-\d-[A-Z0-9]+-\d+-[A-Za-z0-9]+
F ::: Slack-Webhook ::: https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+
F ::: Discord-Bot-Token ::: \b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}
F ::: Discord-Webhook ::: (?i)https://(?:[a-z]+\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+
F ::: Telegram-Bot-Token ::: \b\d{8,10}:AA[A-Za-z0-9_-]{33}\b
F ::: Zapier/IFTTT/Make-Webhook ::: (?i)https://(?:hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]+|maker\.ifttt\.com/trigger/[^\s/]+/with/key/[A-Za-z0-9_-]+|hook\.[a-z0-9.]*make\.com/[A-Za-z0-9]+)
F ::: SendGrid-Key ::: \bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{30,}
F ::: Mailgun-Key ::: \bkey-[0-9a-f]{32}\b
F ::: Mailchimp-Key ::: \b[0-9a-f]{32}-us\d{1,2}\b
F ::: Resend-Key ::: \bre_(?=[A-Za-z0-9_]*\d)[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b
F ::: Twilio-Key ::: \b(?:SK|AC)[0-9a-f]{32}\b
F ::: Shopify-Token ::: \bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b
F ::: DigitalOcean-Token ::: \bdo[opr]_v1_[a-f0-9]{64}\b
F ::: Supabase-Key ::: \b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,})
F ::: Firebase-FCM-Key ::: \bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
F ::: Notion-Token ::: \b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b
F ::: Linear-Key ::: \blin_api_[A-Za-z0-9]{40}\b
F ::: Figma-Token ::: \bfig[dou]r?_[A-Za-z0-9_-]{40,}
F ::: Postman-Key ::: \bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b
F ::: Sentry-Token ::: \bsntry[su]_[A-Za-z0-9+/=_-]{40,}
F ::: Grafana-Token ::: \bgl(?:sa|c)_[A-Za-z0-9+/=_]{32,}
F ::: NewRelic-Key ::: \bNR(?:AK|II|JS)-[A-Za-z0-9]{27,}\b
F ::: Vault-Token ::: \bhv[sb]\.[A-Za-z0-9_-]{24,}
F ::: Terraform-Token ::: \b[a-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}
F ::: Doppler-Token ::: \bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}
F ::: Pulumi-Token ::: \bpul-[a-f0-9]{40}\b
F ::: Databricks-Token ::: \bdapi[a-f0-9]{32}(?:-\d)?\b
F ::: Dropbox-Token ::: \bsl\.[A-Za-z0-9_-]{130,}
F ::: 1Password-Token ::: \bops_eyJ[A-Za-z0-9+/=_-]{100,}
F ::: Cloudflare-Origin-Key ::: \bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b
F ::: PlanetScale-Token ::: \bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}
F ::: Fly.io-Token ::: \b(?:fo1_[A-Za-z0-9_-]{40,}|FlyV1 fm\d_[A-Za-z0-9+/=,_-]{100,})
F ::: Netlify-Token ::: \bnf[pcbo]_[A-Za-z0-9]{36,}\b
F ::: Render-Key ::: \brnd_[A-Za-z0-9]{32}\b
F ::: Heroku-Key ::: \bHRKU-[A-Za-z0-9_-]{58,}
F ::: Square-Token ::: \bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}
F ::: Facebook-Token ::: \bEAA[A-Za-z0-9]{80,}\b
F ::: Twitch-Token ::: \boauth:[a-z0-9]{30}\b
F ::: Mapbox-Secret ::: \bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}
F ::: Airtable-Token ::: \bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b
F ::: Dynatrace-Token ::: \bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b
F ::: Vercel-Token ::: \bvc[pkiar]_(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{24,}\b
F ::: Clerk/Lemon/Paddle-Key ::: \b(?:pdl_(?:live|sdbx)_apikey_[A-Za-z0-9_]{30,}|lmsq_[A-Za-z0-9_]{30,})
F ::: Expo/EAS-Token (Kontext) ::: (?i)\bEXPO_TOKEN\s*[=:]\s*["']?(?<s>[A-Za-z0-9_-]{20,})

# ---------- Homeserver / privat ----------
F ::: Tailscale-Key ::: \btskey-[a-z]+-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?
F ::: Riot-API-Key ::: \bRGAPI-[0-9a-fA-F-]{36}
F ::: HenrikDev-API-Key ::: \bHDEV-[0-9a-fA-F-]{36}
F ::: ntfy-Token ::: \btk_[a-z0-9]{29}\b
F ::: Portainer-Token ::: \bptr_[A-Za-z0-9+/=]{30,}
F ::: Authentik-Token ::: \bak-[a-z0-9-]+-[A-Za-z0-9]{20,}\b
F ::: Home-Assistant/Immich/Jellyfin-Key (Kontext) ::: (?i)\b(?:jellyfin|emby|immich|authentik|beszel|nextcloud|omv|adguard|tmdb|gumroad|higgsfield|henrik|overwolf|riot)[A-Za-z0-9_.-]{0,20}(?:key|token|secret|pass(?:word)?)["']?\s*[:=]\s*["']?(?<s>[A-Za-z0-9+/_=-]{16,})
F ::: MediaBrowser-Token ::: (?i)\bMediaBrowser\b[^\r\n]*?\bToken="(?<s>[^"]{8,})"
W ::: rclone-Passwort ::: (?i)\b(?:pass|password|bearer_token|client_secret|token)\s*=\s*(?<s>[A-Za-z0-9_-]{20,})(?=[:,'"\s]|$)

F ::: Uptime-Kuma-Key ::: \buk\d+_[A-Za-z0-9_-]{30,}
F ::: Proxmox-API-Token ::: (?i)\bPVEAPIToken=[^\s=]+=(?<s>[0-9a-f-]{36})
F ::: Hex-Key mit Kontext (Jellyfin/Sonarr/Gitea/Paperless/Pi-hole/Azure OpenAI) ::: (?im)^(?=[^\r\n]*(?:api|key|token|secret|auth|passw|pwd|bearer|credential|schl\S{1,2}ssel|zugang))(?![^\r\n]*(?:sha-?\d|md5|hash|commit|checksum|pr\S{1,2}fsumme|digest|integrity|fingerprint|thumbprint|etag|uuid|guid|revision))[^\r\n]*?(?<![0-9a-fA-F-])(?<s>[0-9a-f]{32,128}|[0-9A-F]{32,128})(?![0-9a-fA-F-])
F ::: UUID-Token mit Kontext ::: (?i)\b[A-Za-z0-9_.-]*(?:token|secret|api[_-]?key|apikey|passw(?:or[dt])?|pwd)[A-Za-z0-9_.-]*["']?\s*[:=]\s*["']?(?<s>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b
F ::: Docker-Compose-Secret ::: (?im)^\s*-\s*["']?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ENCRYPTION_KEY|JWT_KEY|APP_KEY|SALT)[A-Z0-9_]*=(?<s>[^\s"'$][^\s"']{3,})
F ::: NVIDIA-Key ::: \bnvapi-[A-Za-z0-9_-]{40,}
F ::: Voyage-Key ::: \bpa-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{30,}
F ::: Firecrawl-Key ::: \bfc-[a-f0-9]{32}\b
F ::: Jina-Key ::: \bjina_[A-Za-z0-9]{40,}
F ::: Brave-Search-Key ::: \bBSA[A-Za-z0-9_-]{27,}\b
F ::: Runway-Key ::: \bkey_[a-f0-9]{100,}\b

# ---------- Passwort-Hashes / Dumps ----------
F ::: bcrypt-Hash ::: \$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}
F ::: Argon2-Hash ::: \$argon2(?:id|i|d)\$v=\d+\$[^\s"']+
F ::: crypt-Hash (shadow/htpasswd) ::: \$(?:1|5|6|y|7|apr1|scrypt|pbkdf2(?:-sha\d+)?)\$[./A-Za-z0-9$=,+-]{20,}
F ::: Django-Hash ::: \bpbkdf2_sha(?:1|256)\$\d+\$[^\s"']+
F ::: NTLM-Hash-Paar ::: \b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b
F ::: NetNTLM-Hash ::: \b[^\s:]{1,40}::[^\s:]{0,40}:[a-fA-F0-9]{16}:[a-fA-F0-9]{32,}:[a-fA-F0-9]{40,}
F ::: Kerberoast-Hash ::: \$krb5(?:tgs|asrep|pa)\$\d+\$[^\s"']{40,}

# ---------- Krypto-Wallets ----------
F ::: Bitcoin-Privatschluessel (WIF) ::: (?<![A-Za-z0-9])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])
F ::: Extended-Private-Key ::: \b[xyzt]prv[1-9A-HJ-NP-Za-km-z]{100,}

# ---------- Herstellerpraefix + Zufallsteil (generisch) ----------
W ::: Praefix_Hex-Token ::: (?i)\b(?!(?:sha|md|git|commit|hash|checksum|etag|rev|build|image|digest|uuid|guid|id|trace|span|request|req|correlation)[0-9]*[_-])[a-z][a-z0-9]{1,24}(?:[_-][a-z0-9]{1,16}){0,4}[_-](?<s>[0-9a-f]{16,128})(?![0-9a-zA-Z])
W ::: Praefix_Token ::: (?i)\b(?:[a-z][a-z0-9]{1,24}[_-]){1,5}(?:key|secret|token|pat|sk|pk|ak|apikey|whsec|pw|pass|password|sandbox|live|test|prod|gateway|credential|bearer|auth|admin|master)[_.-](?<s>[A-Za-z0-9~+/=]{16,}(?:[._~-][A-Za-z0-9~+/=_-]{4,})*)
W ::: Token_nach_Schluesselwort_im_Namen ::: (?i)\b[a-z][a-z0-9]{1,24}(?:[_-][a-z0-9]{1,16}){0,4}[_-](?:key|secret|token|pat|apikey|whsec|credential|password|passwd)[_-](?<s>[A-Za-z0-9~+/=]{16,}(?:[._~-][A-Za-z0-9~+/=_-]{4,})*)
F ::: Praefix_UUID-Token ::: (?i)\b[a-z][a-z0-9]{1,24}(?:[_-][a-z0-9]{1,16}){0,3}[_-](?:key|secret|token|pat|sk|pk|ak|sandbox|live|test|prod|auth|cred|pass|whsec|bearer|access|private|admin|master|service|webhook|session|license)[_-][a-z0-9_-]{0,16}?(?<s>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b
F ::: Praefix_sk/pk_Token ::: (?i)\b(?:sk|pk|rk|whsec)[_-](?:test|live|prod|sandbox)[_-][a-z0-9_-]{8,}
F ::: Service-Token mit Punkt ::: (?i)\b[a-z][a-z0-9]{1,20}_(?:st|sk|pk|at|rt|sat|pat|svc|key)\.[A-Za-z0-9]{12,}\.[A-Za-z0-9_-]{8,}
W ::: Praefix_lange_Zeichenfolge ::: (?i)\b(?!(?:sha|md|git|commit|hash|checksum|etag|rev|build|image|digest|uuid|guid|trace|span|request|req|correlation)[0-9]*[_-])[a-z][a-z0-9]{1,20}(?:_[a-z0-9]{1,16}){1,4}_(?<s>(?=(?:[A-Za-z0-9]*?(?:[a-z]\d|\d[a-z])){2})[A-Za-z0-9]{8,}(?:[_-][A-Za-z0-9]{4,}){0,5}|(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[a-z])[A-Za-z0-9]{32,})(?![A-Za-z0-9])
W ::: Praefix_pat_Punkt ::: (?i)\b[a-z][a-z0-9]{1,20}_pat[A-Za-z0-9]{10,}\.[0-9a-f]{40,}
W ::: Schluesselwort-Praefix + kurze Segmente ::: (?i)\b[a-z][a-z0-9]{1,20}(?:[_-][a-z0-9]{1,16}){0,4}[_-](?:key|secret|token|pat|pass|password|passwd|pw|cred|credential|auth|authcookie|cookie|bearer|whsec)[_-](?<s>(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[a-z])[A-Za-z0-9]{4,}(?:-[A-Za-z0-9]{4,}){2,})(?![A-Za-z0-9])
W ::: Azure-Secret (Tilde) ::: \b(?<s>(?=[A-Za-z0-9_.~-]*\d)[A-Za-z0-9]{3,10}~[A-Za-z0-9_.~-]{20,})
F ::: Instrumentation-Key ::: (?i)InstrumentationKey\s*=\s*(?<s>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})
W ::: Schluesselwort_Wert (Unterstrich) ::: (?i)(?<![A-Za-z0-9])(?:secret|token|passwort|password|passwd|pass|pw|pwd|apikey|api_key|key|pin|puk|psk|cred)[_-](?<s>(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{6,}(?:[_-][A-Za-z0-9]{4,}){0,3})(?![A-Za-z0-9])
F ::: Airtable-PAT ::: \bpat[A-Za-z0-9]{10,}\.[0-9a-f]{40,}

# ---------- Azure-Schluessel mit eingebauter Signatur, weitere Formate ----------
F ::: Azure-Key (Signatur) ::: (?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}(?:\+ASt|ACDb|\+ASb|\+AEh|\+ARm|AIoT|AzCa|AzSe|AzFu|\+ACR|AZEG|APIM|\+ABa|JQQJ99)[A-Za-z0-9+/_-]{2,}={0,2}
F ::: Entra-Refresh-Token/Auth-Code ::: (?<![A-Za-z0-9._-])[01]\.A[A-Za-z0-9_-]{60,}(?:\.[A-Za-z0-9_-]{10,})*
F ::: StaticWebApp-Token ::: \b[0-9a-f]{40,}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{9,}\b
F ::: DeepL-Key ::: \b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:fx\b
F ::: SOPS-Wert ::: ENC\[AES256_GCM,data:[^\]\r\n]+\]
F ::: OpenSSL-verschluesselt ::: \bU2FsdGVkX1[A-Za-z0-9+/=]{16,}
F ::: Ansible-Vault ::: \$ANSIBLE_VAULT;[0-9.]+;AES256(?:;[\w-]+)?\s*\r?\n[0-9a-f\s]+
F ::: Cisco-Passwort ::: (?i)\b(?:password|secret|key)\s+[0-9]\s+(?<s>\S{8,})
W ::: WLAN-QR-Code ::: WIFI:[^\r\n]*?;P:(?<s>(?:\\.|[^;\r\n])+);
W ::: pgpass-Zeile ::: (?m)^[\w.*-]+:(?:\d{2,5}|\*):[\w.*-]+:[\w.*-]+:(?<s>\S+)[ \t]*\r?$
W ::: mysql -pPasswort ::: (?i)\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\r\n|;&]*?\s-p(?<s>[^\s"']{3,})
W ::: sqlcmd -P ::: \b(?i:sqlcmd|bcp|osql|isql|tsql)(?-i)\b[^\r\n|;&]*?\s-P\s*(?<q>["']?)(?<s>[^\s"']+)\k<q>
W ::: Schluessel (zwei Worte) ::: (?i)\b(?:secret|private|api|access|recovery|geheim\w*|wiederherstellungs\w*|temporary access|zugangs\w*)[ -](?:key|schl\S{1,2}ssel|code|token|pass)\s*[:=]\s*(?<q>["']?)(?<s>[^\s"']{6,})\k<q>

W ::: Schluessel direkt im Satz ::: (?i)\b(?:passwor[dt]|kennwort|token|secret|api[- ]?key|key|schl\S{1,2}ssel)[ \t]+(?-i:(?<s>(?=[A-Za-z0-9_.~+/=-]*\d)(?=[A-Za-z0-9_.~+/=-]*[a-z])(?=[A-Za-z0-9_.~+/=-]*[A-Z])[A-Za-z0-9_.~+/=-]{12,}|(?=[a-z0-9]*\d[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{20,}))(?![A-Za-z0-9])
B ::: Variable key = "..." ::: (?i)(?<![A-Za-z0-9_.-])\$?(?:key|schl\S{1,2}ssel|api|auth)["']?[ \t]*(?:=|:)[ \t]*["'](?<s>[^"'\s]{12,})["']
W ::: Bicep-Parameter ::: (?i)\bparam\s+\w*(?:passw|secret|token|key|pwd|cred)\w*\s+string\s*=\s*'(?<s>[^'\r\n]{4,})'
W ::: Terraform-Variable ::: (?is)\bvariable\s+"[^"]*(?:passw|secret|token|key|pwd|cred)[^"]*"\s*\{[^{}]*?\bdefault\s*=\s*"(?<s>[^"\r\n]{4,})"
# ---------- Kommandozeile ----------
W ::: Login per -p/-pw ::: (?i)\b(?:docker|podman|az|helm|oc|sshpass|plink|pscp|psftp|psexec|winexe|smbclient|mysql|mysqldump|mongosh|redis-cli|xfreerdp|rdesktop|evil-winrm|crackmapexec|nxc|impacket-\w+)\b[^\r\n|;&]*?\s-(?:p|pw|pass|a)\s+(?<q>["']?)(?<s>(?!--?[A-Za-z][A-Za-z-]*(?:\s|$|["']))[^\s"']+)\k<q>
W ::: curl -u ::: (?i)\b(?:curl(?:\.exe)?|wget|http|https|xh|rclone|git)\b[^\r\n|]*?\s(?:-u|--user|--http-user)[ =]+(?<q>["']?)[^\s:"']+:(?<s>[^\s"']+)\k<q>
W ::: Passwort im Satz ::: (?i)\b(?:passwor[dt]|kennwort|passcode|passphrase|pw|pin|token|secret|api[- ]?key|schl\S{1,2}ssel)(?:[ \t]+[A-Za-z\u00C0-\u017F@.-]+){0,5}?[ \t]+(?:ist|lautet|is|war|was|w\S{1,2}re)[ \t]*:?[ \t]+(?<q>["'`]?)(?<s>(?=[^\s"'`]*[^\sA-Za-z"'`.,;:!?]|(?-i:[^\s"'`]*[a-z][A-Z][^\s"'`]*[a-z][A-Z]))[^\s"'`]{4,})\k<q>
'@

$script:KeyWort = 'pass|pwd|pw|kennwort|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|shared[_-]?access|subscription[_-]?key|master[_-]?key|function[_-]?key|app[_-]?key|encryption[_-]?key|signing[_-]?key|license[_-]?key|storage[_-]?key|client[_-]?key|consumer[_-]?key|auth[_-]?key|instrumentation[_-]?key|key[_-]?data|keymaterial|credential|cred|connection[_-]?string|connstr|sas|bearer|cookie|session[_-]?(?:id|key)|pin|otp|mnemonic|recovery|seed[_-]?phrase|webhook|dsn'

# Stichwort + Wert:  password=abc   "client_secret": "abc"   $token = 'abc'   DB_PASS: abc
$script:RxKv = New-Object regex (('(?i)(?<![A-Za-z0-9_.-])(?<k>[A-Za-z0-9_.-]{0,40}?(?:KW)[A-Za-z0-9_.-]{0,24}?)["''`]?(?<pre>[ \t]*)(?<op>=>|:=|[:=])(?![=>])(?<post>[ \t]*)(?:(?<q>["''`])(?<s>[^"''`\r\n]{3,8000})\k<q>|(?<s>[^\s"''`]{4,8000}))').Replace('KW', $script:KeyWort)), ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(1500))
$script:RxWertEnde = New-Object regex '[;,&](?=[\w.\- \[\]]{1,40}=)|[;,&]$|</?[A-Za-z!?][^<>\s]*>|>(?=\s|$)'
# Schalter + Wert:   --client-secret abc   -Password "abc"   --token=abc
$script:RxFlag = New-Object regex (('(?i)(?<![A-Za-z0-9])(?<k>--?[A-Za-z0-9-]*(?:KW)[A-Za-z0-9-]*)(?:[ \t]+|[=:])(?:(?<q>["''])(?<s>[^"''\r\n]{3,500})\k<q>|(?<s>[^\s"''|;<>-][^\s"''|;<>]{2,500}))').Replace('KW', $script:KeyWort)), ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(1500))
# XML:               <Password>abc</Password>
$script:RxXml = New-Object regex (('(?i)<(?<k>[A-Za-z0-9_:.-]*(?:KW)[A-Za-z0-9_:.-]*)(?:\s[^>]*)?>(?<s>[^<\r\n]{3,500})</\k<k>>').Replace('KW', $script:KeyWort)), ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(1500))

$script:RxKeyJa = New-Object regex '(?:^|_)(?:[a-z0-9]*(?:password|passwort|passwd|kennwort|passphrase|passcode|secret|token|apikey|pwd)|pass|pw|pin|sas|creds?|credentials?|bearer|cookie|otp|totp|mnemonic|connstr|dsn|keymaterial|webhook|(?:api|access|account|private|subscription|master|function|app|encryption|signing|license|auth|secret|shared_access|recovery|consumer|storage|client)_key|key_data|shared_access_signature|connection_string|[a-z]*connectionstring|[a-z]*accesskey|[a-z]*instrumentationkey|accountkey|session_(?:id|key)|recovery_codes?|seed_phrase)(?:_|$)'
$script:KeyNein = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($w in 'count,limit,length,len,type,types,url,uri,endpoint,name,names,id,ids,path,file,dir,expires,expiry,expiration,ttl,max,min,size,policy,hint,prompt,label,field,required,enabled,valid,validity,lifetime,usage,budget,price,cost,input,output,version,format,algorithm,alg,header,prefix,suffix,placeholder,regex,pattern,rule,rules,exists,present,mode,consent,banner,domain,samesite,secure,httponly'.Split(',')) { [void]$script:KeyNein.Add($w) }

$script:WertNein = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($w in 'password,passwort,kennwort,secret,token,string,text,true,false,null,none,undefined,nil,required,optional,yes,no,ja,nein,hidden,redacted,env,file,prompt,bearer,basic,oauth,oauth2,api_key,apikey,jwt,key,value,wert,leer,empty,changeme,geheim,******,unknown,default,auto,required,invalid,expired,missing,falsch,richtig,wrong,correct,ungueltig,abgelaufen,fehlt'.Split(',')) { [void]$script:WertNein.Add($w) }

$script:RxPlatzhalter = New-Object regex '(?i)^(?:dein|deine|your|mein|meine|my|ihr|some|new|neues|old|altes)[-_ A-Za-z]*$|(?-i:^(?:[A-Z]?[a-z]+|[A-Z]+)(?:[-_](?:[A-Z]?[a-z]+|[A-Z]+))+$)|example|beispiel|placeholder|platzhalter|change-?me|dummy|todo|^x{3,}|^\*{3,}|^\.{3,}|^-+$|^_+$|REDACTED'
$script:RxCode        = New-Object regex '^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$|^[A-Za-z_][A-Za-z0-9_]*::|^(?:os|process|env|secrets|vars|config|settings|self|this|args|params|request|req|response|res|data|options|opts)\b'
$script:RxUrl         = New-Object regex '(?i)\b(?:https?|ftp|file)://[^\s"''<>]+'
$script:RxEntropie    = New-Object regex '(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,60000}={0,2}(?![A-Za-z0-9+/_=-])'
$script:RxKarte       = New-Object regex '(?<![\d.,-])(?:\d[ -]?){12,18}\d(?![\d.,-])'
$script:RxKartenTyp   = New-Object regex '^(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d\d)\d{12})$'

# =====================================================================================================
#  ENGINE
# =====================================================================================================
$script:Regeln   = New-Object System.Collections.ArrayList
$script:GlRegeln = New-Object System.Collections.ArrayList
$script:Gemerkt  = New-Object 'System.Collections.Generic.List[object]'
$script:Originale = New-Object 'System.Collections.Generic.List[object]'

function Add-Regel([string]$Art, [string]$Name, [string]$Muster) {
    try {
        $rx = New-Object regex $Muster, ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(800))
        # Hat die Regel ein woertliches Erkennungsstueck (ghp_, AKIA, -----BEGIN ...)? Nur solche gelten auch fuer ROT13/rueckwaerts
        $kern = $Muster -replace '\(\?<?![^)]*\)', ' ' -replace '\\[A-Za-z]', ' ' -replace '\[[^\]]*\]', ' ' -replace '\(\?<?[A-Za-z!=:-]*>?', ' '
        $lit = (($kern -cmatch '[A-Za-z][A-Za-z_-]{3,}') -or ($Muster.Contains('://'))) -and ($Name -notmatch '^(?:Praefix|Schluesselwort|Token_nach|Hex-Key|UUID-Token)')
        [void]$script:Regeln.Add([pscustomobject]@{ Art = $Art; Name = $Name; Rx = $rx; Lit = $lit })
    } catch {
        Write-Warning "Regel '$Name' ungueltig: $($_.Exception.Message)"
    }
}

function Import-RegelTabelle([string]$Tabelle) {
    foreach ($z in ($Tabelle -split "`r?`n")) {
        $z = $z.Trim()
        if (-not $z -or $z.StartsWith('#')) { continue }
        $t = $z -split ' ::: ', 3
        if ($t.Count -eq 3) { Add-Regel $t[0].Trim() $t[1].Trim() $t[2] }
    }
}

# Eigene Regeln:  literal:Text   oder   regex:Muster   (eine pro Zeile, # = Kommentar)
function Import-Eigene {
    if (-not (Test-Path -LiteralPath $script:EigenePfad)) { return }
    $n = 0
    foreach ($z in (Get-Content -LiteralPath $script:EigenePfad -Encoding UTF8)) {
        $z = $z.Trim()
        if (-not $z -or $z.StartsWith('#')) { continue }
        $n++
        if ($z -like 'literal:*')   { Add-Regel 'F' "Eigene Regel $n" ('(?i)' + [regex]::Escape($z.Substring(8).Trim())) }
        elseif ($z -like 'regex:*') { Add-Regel 'F' "Eigene Regel $n" $z.Substring(6).Trim() }
    }
}

# gitleaks.toml einlesen (nur id, regex, entropy, keywords, secretGroup)
function Import-Gitleaks([string]$Pfad) {
    $script:GlRegeln.Clear()
    if (-not (Test-Path -LiteralPath $Pfad)) { return 0 }
    $roh = [IO.File]::ReadAllText($Pfad)
    $bloecke = [regex]::Split($roh, '(?m)^\[\[rules\]\]\s*$')
    $skip = 0
    for ($i = 1; $i -lt $bloecke.Count; $i++) {
        $b = $bloecke[$i]
        $mId = [regex]::Match($b, '(?m)^id\s*=\s*"([^"]+)"')
        $mRx = [regex]::Match($b, "(?m)^regex\s*=\s*'''(.+?)'''\s*$")
        if (-not $mId.Success -or -not $mRx.Success) { continue }
        $id = $mId.Groups[1].Value
        if ($id -eq 'generic-api-key') { continue }          # dafuer gibt es die eigene Stichwort-Erkennung
        $p = $mRx.Groups[1].Value
        if ($p.Contains('[[:')) { $skip++; continue }        # POSIX-Klassen kann .NET nicht
        $p = $p.Replace('(?P<', '(?<')
        $ent = 0.0
        $mE = [regex]::Match($b, '(?m)^entropy\s*=\s*([\d.]+)')
        if ($mE.Success) { $ent = [double]::Parse($mE.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) }
        $grp = 0
        $mG = [regex]::Match($b, '(?m)^secretGroup\s*=\s*(\d+)')
        if ($mG.Success) { $grp = [int]$mG.Groups[1].Value }
        $kw = @()
        $mK = [regex]::Match($b, '(?ms)^keywords\s*=\s*\[(.*?)\]')
        if ($mK.Success) { $kw = @([regex]::Matches($mK.Groups[1].Value, '"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value.ToLower() }) }
        try {
            $rx = New-Object regex $p, ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(400))
            [void]$script:GlRegeln.Add([pscustomobject]@{ Name = "gitleaks:$id"; Rx = $rx; Ent = $ent; Grp = $grp; Kw = $kw })
        } catch { $skip++ }
    }
    return $script:GlRegeln.Count
}

function Get-Entropie([string]$s) {
    if (-not $s) { return 0.0 }
    $h = @{}
    foreach ($c in $s.ToCharArray()) { if ($h.ContainsKey($c)) { $h[$c]++ } else { $h[$c] = 1 } }
    $e = 0.0
    foreach ($v in $h.Values) { $p = $v / $s.Length; $e -= $p * [math]::Log($p, 2) }
    return $e
}

# Sieht ein Token nach Zufall aus?  Gemischt (aB3...) ab 20 Zeichen, einfarbig (ab3... / AB3...) ab 30 Zeichen.
# ---------- Zufalls-Erkennung ----------
$script:Bigramme = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($b in 'ab ac ad al am an ap ar as at bl ca ce ch ck co ct da de di ea ec ed eg el em en er es et ex fi fo ge gr ha he ic id ie ig il im in io is it ke la le li ll lo lt ma me mi mp na nc nd ne ng ni no ns nt od ol om on op or ot ou pa pe pl po pr pt ra re ri ro rr rs rt se si so ss st ta te th ti to tr ts ty ul um un ur ut va ve wi yp'.Split(' ')) { [void]$script:Bigramme.Add($b) }

function Test-Zufall([string]$v) {
    $t = $v.TrimEnd('=')
    if ($t -match '^[0-9a-fA-F-]+$') { return $false }          # Hashes, GUIDs, Commit-IDs: eigene Stufe
    # Alphabet-/Zeichensatz-Folgen (abcdef..., bcdeEfFgG...) sind kein Zufall
    $kleinT = $t.ToLowerInvariant(); $sortiert = 0
    for ($i = 1; $i -lt $kleinT.Length; $i++) { if ($kleinT[$i - 1] -le $kleinT[$i]) { $sortiert++ } }
    if ($t.Length -ge 8 -and ($sortiert / ($t.Length - 1)) -ge 0.85) { return $false }
    $stuecke = @($t -split '[_-]')
    $teile = @($stuecke | Where-Object { $_ -cmatch '^(?:\d{4,}|[a-z]{4,}|[A-Z]{4,}|[A-Z][a-z]{3,})$' })
    if ($teile.Count -ge 2) { return $false }                   # Dateinamen, Bezeichner mit Woertern/Datumsbloecken
    $z  = ([regex]::Matches($t, '\d')).Count
    $kl = $t -cmatch '[a-z]'
    $gr = $t -cmatch '[A-Z]'
    $e  = Get-Entropie $t
    if ($kl -and $gr) {
        if ($t.Length -ge 24) { if ($z -ge 2 -and $e -ge 4.0) { return $true } }
        elseif ($z -ge 3 -and $e -ge 3.9) { return $true }
        # Ohne (genug) Ziffern: echte Bezeichner bestehen aus Woertern, Zufall nicht
        if ($t.Length -lt 20 -or $e -lt 3.5) { return $false }
        foreach ($s in $stuecke) { if ($s.Length -ge 8 -and $s -cmatch '^[a-z]*(?:[A-Z][a-z]{2,}){2,}$') { return $false } }
        $an = ([regex]::Matches($t, '[A-Za-z0-9]')).Count
        $lang = 0
        foreach ($m in [regex]::Matches($t, '[a-z]{3,}')) { $lang += $m.Length }
        $w = $lang / [math]::Max(1, $an)                        # Anteil der Zeichen in Kleinbuchstaben-Folgen (Woerter)
        if ($w -lt 0.45) { return $true }
        if ($w -ge 0.65) { return $false }
        $paare = [regex]::Matches($t, '(?=([A-Za-z]{2}))')
        if ($paare.Count -lt 10) { return $false }
        $gut = 0
        foreach ($p in $paare) { if ($script:Bigramme.Contains($p.Groups[1].Value.ToLowerInvariant())) { $gut++ } }
        return (($gut / $paare.Count) -le 0.34)
    }
    if ($t.Length -lt 30 -or -not ($kl -or $gr)) { return $false }
    $anteil = $z / $t.Length
    if ($anteil -lt 0.15 -or $anteil -gt 0.85) { return $false }
    $wechsel = ([regex]::Matches($t, '(?<=[A-Za-z])\d|(?<=\d)[A-Za-z]')).Count
    return ($wechsel -ge 8 -and $e -ge 3.6)
}

function Test-Bereich($Liste, [int]$Index) {
    foreach ($u in $Liste) { if ($Index -ge $u.Index -and $Index -lt ($u.Index + $u.Length)) { return $true } }
    return $false
}

# ---------- Dekodieren ("Mathe"): Base64, Hex, Base32, Base85, gzip/zlib/zip, Escapes ----------
$script:Unlesbar = [string][char]0xFFFF + 'UNLESBAR'
$script:RxB64Kand   = New-Object regex '(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,60000}={0,2}(?![A-Za-z0-9+/_=-])'
$script:RxB64Block  = New-Object regex '(?:[A-Za-z0-9+/]{40,100}\r?\n){1,}[A-Za-z0-9+/]*={0,2}'
$script:RxHexKand   = New-Object regex '(?<![A-Za-z0-9])(?:[0-9a-fA-F]{2}){12,30000}(?![A-Za-z0-9])|(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}[ :-]){11,}[0-9a-fA-F]{2}(?![0-9A-Za-z])|(?:0x[0-9a-fA-F]{2}(?:\s*,\s*|\s+)){7,}0x[0-9a-fA-F]{2}|(?:\\x[0-9a-fA-F]{2}){8,}|(?:%[0-9a-fA-F]{2}){8,}|(?:=[0-9A-F]{2}){8,}'
$script:RxDezKand   = New-Object regex '(?<![\d.,])(?:\d{1,3}\s*,\s*){11,}\d{1,3}(?![\d.])'
$script:RxBinKand   = New-Object regex '(?<![01])(?:[01]{8}[ ,]+){7,}[01]{8}(?![01])'
$script:RxB32Kand   = New-Object regex '(?<![A-Za-z0-9])[A-Z2-7]{24,}={0,6}(?![A-Za-z0-9=])'
$script:RxA85Kand   = New-Object regex '<~([\x21-\x75z\s]{10,}?)~>'
$script:RxB85Kand   = New-Object regex '(?<!\S)[0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~-]{20,4000}(?!\S)'
$script:RxUUKand    = New-Object regex 'begin [0-7]{3} \S+\r?\n((?:[\x20-\x60]{1,62}\r?\n)+?)(?:`\r?\n)?end'
$script:RxEscape    = New-Object regex '%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#[xX][0-9a-fA-F]{1,4};|&#\d{1,5};|&(?:amp|lt|gt|quot|apos);'
$script:RxEscLaufVor  = New-Object regex '(?:(?:%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#[xX]?[0-9a-fA-F]{1,5};)){3,}$', ([System.Text.RegularExpressions.RegexOptions]::RightToLeft)
$script:RxEscLaufNach = New-Object regex '\G(?:(?:%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#[xX]?[0-9a-fA-F]{1,5};)){3,}'
$script:RxOeffentlich = New-Object regex '-----BEGIN (?<a>CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|X509 CRL|PGP PUBLIC KEY BLOCK|PGP SIGNATURE)-----[\s\S]*?-----END \k<a>-----|\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) AAAA[A-Za-z0-9+/=]+|data:(?:image|font|audio|video)/[\w.+-]+;base64,[A-Za-z0-9+/=]+'
$script:RxHexNackt  = New-Object regex '(?<![A-Za-z0-9_+/.-])[0-9a-fA-F]{32,}(?![A-Za-z0-9_+/=-])(?!\.\.)'
$script:RxHashKontext = New-Object regex '(?i)(?:sha-?\d{0,3}|md5|hash|hashes|checksum|pr\S{1,2}fsumme|digest|commit|merge|parent|tree|blob|rev|revision|etag|thumbprint|fingerprint|fingerabdruck|checkout|cherry-pick|revert|reset|bisect|show|tag|git \S+|\bids?|guid|uuid|trace|span|object)[\s\W]{0,20}$'
$script:RxSymbol    = New-Object regex '(?<![^\s"''`(>|])[A-Za-z0-9][A-Za-z0-9._~\[\]:?@=+/-]{22,62}[A-Za-z0-9~_\[\]=+/@?:.-](?=$|[\s"''`)<|]|[,;!](?:\s|$))'

function Test-Lesbar([string]$s) {
    if (-not $s -or $s.Length -lt 4) { return $false }
    $n = ([regex]::Matches($s, '[\x20-\x7E\r\n\t -ſ]')).Count
    return (($n / $s.Length) -ge 0.92)
}

function Expand-Daten([byte[]]$b, [string]$Art) {
    $ein = New-Object System.IO.MemoryStream (, $b)
    $aus = New-Object System.IO.MemoryStream
    try {
        if ($Art -eq 'zip') {
            $zip = New-Object System.IO.Compression.ZipArchive ($ein, [System.IO.Compression.ZipArchiveMode]::Read)
            $nr = 0
            foreach ($e in $zip.Entries) {
                if ($nr++ -ge 20 -or $aus.Length -gt 1000000) { break }
                $st = $e.Open(); $puf = New-Object byte[] 65536
                while (($n = $st.Read($puf, 0, $puf.Length)) -gt 0 -and $aus.Length -lt 1000000) { $aus.Write($puf, 0, $n) }
                $st.Dispose(); $aus.WriteByte(10)
            }
        } else {
            if ($Art -eq 'zlib') { $ein.Position = 2 }
            if ($Art -eq 'gzip') { $st = New-Object System.IO.Compression.GZipStream ($ein, [System.IO.Compression.CompressionMode]::Decompress) }
            else                 { $st = New-Object System.IO.Compression.DeflateStream ($ein, [System.IO.Compression.CompressionMode]::Decompress) }
            $puf = New-Object byte[] 65536
            while (($n = $st.Read($puf, 0, $puf.Length)) -gt 0 -and $aus.Length -lt 1000000) { $aus.Write($puf, 0, $n) }
            $st.Dispose()
        }
        return , $aus.ToArray()
    } finally { $ein.Dispose(); $aus.Dispose() }
}

# Bytes -> lesbarer Text, $null (kein Text) oder $script:Unlesbar (komprimiert/verschluesselt und nicht pruefbar)
function ConvertFrom-Bytes([byte[]]$b, [bool]$DeflateVersuch = $false, [int]$Stufe = 0) {
    if ($null -eq $b -or $b.Length -lt 4) { return $null }
    $art = $null
    if ($b[0] -eq 0x1f -and $b[1] -eq 0x8b) { $art = 'gzip' }
    elseif ($b[0] -eq 0x78 -and ((($b[0] * 256 + $b[1]) % 31) -eq 0) -and $b.Length -ge 8) { $art = 'zlib' }
    elseif ($b[0] -eq 0x50 -and $b[1] -eq 0x4b -and $b[2] -eq 3 -and $b[3] -eq 4) { $art = 'zip' }
    if ($art) {
        try { $roh = Expand-Daten $b $art } catch { if ($art -eq 'zlib') { $roh = $null; $art = $null } else { return $script:Unlesbar } }
        if ($art) {
            if ($Stufe -ge 3) { return $script:Unlesbar }
            $t = ConvertFrom-Bytes $roh $false ($Stufe + 1)
            if ($null -eq $t) { return $script:Unlesbar }
            return $t
        }
    }
    # andere Packer / Container, die sich hier nicht auspacken lassen
    if (($b[0] -eq 0x42 -and $b[1] -eq 0x5a -and $b[2] -eq 0x68) -or
        ($b[0] -eq 0xfd -and $b[1] -eq 0x37 -and $b[2] -eq 0x7a -and $b[3] -eq 0x58) -or
        ($b[0] -eq 0x37 -and $b[1] -eq 0x7a -and $b[2] -eq 0xbc -and $b[3] -eq 0xaf) -or
        ($b[0] -eq 0x28 -and $b[1] -eq 0xb5 -and $b[2] -eq 0x2f -and $b[3] -eq 0xfd) -or
        ($b[0] -eq 0x52 -and $b[1] -eq 0x61 -and $b[2] -eq 0x72 -and $b[3] -eq 0x21) -or
        ($b[0] -eq 0x04 -and $b[1] -eq 0x22 -and $b[2] -eq 0x4d -and $b[3] -eq 0x18)) { return $script:Unlesbar }
    if ($b.Length -ge 8 -and ($b.Length % 2) -eq 0) {
        $null0 = 0
        for ($i = 1; $i -lt [math]::Min($b.Length, 400); $i += 2) { if ($b[$i] -eq 0) { $null0++ } }
        if ($null0 -ge ([math]::Min($b.Length, 400) / 2) * 0.8) {
            $s = [System.Text.Encoding]::Unicode.GetString($b)
            if (Test-Lesbar $s) { return $s }
        }
    }
    $s = [System.Text.Encoding]::UTF8.GetString($b)
    if (Test-Lesbar $s) { return $s }
    if ($DeflateVersuch -and $b.Length -ge 12 -and $Stufe -lt 3) {
        try {
            $roh = Expand-Daten $b 'deflate'
            if ($roh.Length -ge 8) { $t = ConvertFrom-Bytes $roh $false ($Stufe + 1); if ($t -and $t -ne $script:Unlesbar) { return $t } }
        } catch { }
    }
    return $null
}

function ConvertFrom-HexText([string]$h) {
    if ($h.Length -gt 40000) { $h = $h.Substring(0, 40000) }
    $n = [int][math]::Floor($h.Length / 2)
    $b = New-Object byte[] $n
    for ($i = 0; $i -lt $n; $i++) { $b[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
    return , $b
}

function ConvertFrom-Base32([string]$s) {
    $s = $s.TrimEnd('='); $bits = 0; $wert = 0
    $ms = New-Object System.IO.MemoryStream
    foreach ($c in $s.ToCharArray()) {
        $i = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.IndexOf($c)
        if ($i -lt 0) { return $null }
        $wert = (($wert -shl 5) -bor $i) -band 0xFFFFF; $bits += 5
        if ($bits -ge 8) { $bits -= 8; $ms.WriteByte([byte](($wert -shr $bits) -band 0xFF)) }
    }
    return , $ms.ToArray()
}

function ConvertFrom-Base85([string]$s, [string]$Alphabet, [bool]$Adobe) {
    $ms = New-Object System.IO.MemoryStream
    $grp = New-Object 'System.Collections.Generic.List[long]'
    foreach ($c in $s.ToCharArray()) {
        if ([char]::IsWhiteSpace($c)) { continue }
        if ($Adobe -and $c -eq 'z' -and $grp.Count -eq 0) { $ms.Write((New-Object byte[] 4), 0, 4); continue }
        $i = $Alphabet.IndexOf($c)
        if ($i -lt 0) { return $null }
        $grp.Add($i)
        if ($grp.Count -eq 5) {
            [long]$w = 0; foreach ($g in $grp) { $w = $w * 85 + $g }
            if ($w -gt 4294967295) { return $null }
            $ms.WriteByte([byte](($w -shr 24) -band 255)); $ms.WriteByte([byte](($w -shr 16) -band 255)); $ms.WriteByte([byte](($w -shr 8) -band 255)); $ms.WriteByte([byte]($w -band 255))
            $grp.Clear()
        }
    }
    if ($grp.Count -eq 1) { return $null }
    if ($grp.Count -gt 1) {
        $n = $grp.Count
        while ($grp.Count -lt 5) { $grp.Add(84) }
        [long]$w = 0; foreach ($g in $grp) { $w = $w * 85 + $g }
        if ($w -gt 4294967295) { return $null }
        $alle = @([byte](($w -shr 24) -band 255), [byte](($w -shr 16) -band 255), [byte](($w -shr 8) -band 255), [byte]($w -band 255))
        for ($i = 0; $i -lt ($n - 1); $i++) { $ms.WriteByte($alle[$i]) }
    }
    return , $ms.ToArray()
}

function ConvertFrom-UU([string]$Block) {
    $ms = New-Object System.IO.MemoryStream
    foreach ($z in ($Block -split '\r?\n')) {
        if ($z.Length -lt 2) { continue }
        $n = ([int]$z[0] - 32) -band 63
        if ($n -eq 0) { break }
        $v = New-Object 'System.Collections.Generic.List[int]'
        for ($i = 1; $i -lt $z.Length; $i++) { $v.Add((([int]$z[$i] - 32) -band 63)) }
        while (($v.Count % 4) -ne 0) { $v.Add(0) }
        $o = New-Object 'System.Collections.Generic.List[byte]'
        for ($i = 0; $i -lt $v.Count; $i += 4) {
            $w = ($v[$i] -shl 18) -bor ($v[$i + 1] -shl 12) -bor ($v[$i + 2] -shl 6) -bor $v[$i + 3]
            $o.Add([byte](($w -shr 16) -band 255)); $o.Add([byte](($w -shr 8) -band 255)); $o.Add([byte]($w -band 255))
        }
        for ($i = 0; $i -lt [math]::Min($n, $o.Count); $i++) { $ms.WriteByte($o[$i]) }
    }
    return , $ms.ToArray()
}

# Dekodierten Inhalt pruefen; steckt ein Secret drin, wird der ganze kodierte Block geschwaerzt
function Add-Kodiert($sp, [int]$Index, [int]$Laenge, [byte[]]$Bytes, [string]$Art, [int]$Tiefe, [bool]$DeflateVersuch = $false) {
    $klar = ConvertFrom-Bytes $Bytes $DeflateVersuch
    if ($null -eq $klar) { return }
    if ($klar -eq $script:Unlesbar) { Add-Span $sp $Index $Laenge "Gepackt/nicht pruefbar ($Art)"; return }
    $in = Find-Secrets $klar ($Tiefe + 1)
    if ($in.Count -gt 0) { Add-Span $sp $Index $Laenge ("Kodiert ($Art): " + $in[0].N) }
}

function Find-Kodiert($sp, [string]$Text, [int]$Tiefe) {
    # Base64 (auch URL-sicher, UTF-16, gzip/zlib/zip darin)
    foreach ($m in $script:RxB64Kand.Matches($Text)) {
        $v = $m.Value
        if ($v -match '^[0-9a-fA-F]+$' -or $v -cmatch '^[a-z]+$' -or $v -cmatch '^[A-Z_]+$') { continue }
        $k = $v.TrimEnd('=').Replace('-', '+').Replace('_', '/')
        if (($k.Length % 4) -eq 1) { continue }
        $k = $k + ('=' * ((4 - ($k.Length % 4)) % 4))
        try { $b = [Convert]::FromBase64String($k) } catch { continue }
        Add-Kodiert $sp $m.Index $m.Length $b 'Base64' $Tiefe ($v.Length -ge 24 -and $v -cmatch '[A-Z]' -and $v -cmatch '[a-z]' -and $v -match '[0-9+/_-]')
    }
    foreach ($m in $script:RxB64Block.Matches($Text)) {
        $k = ($m.Value -replace '\s', '').TrimEnd('=')
        if (($k.Length % 4) -eq 1) { continue }
        $k = $k + ('=' * ((4 - ($k.Length % 4)) % 4))
        try { $b = [Convert]::FromBase64String($k) } catch { continue }
        Add-Kodiert $sp $m.Index $m.Length $b 'Base64, umgebrochen' $Tiefe $true
    }
    # Hex in allen Schreibweisen (ab12..., AB:12:..., 0xab, \xab, %AB, =AB)
    foreach ($m in $script:RxHexKand.Matches($Text)) {
        $h = $m.Value -replace '0x', '' -replace '[^0-9a-fA-F]', ''
        if (($h.Length % 2) -ne 0) { continue }
        Add-Kodiert $sp $m.Index $m.Length (ConvertFrom-HexText $h) 'Hex' $Tiefe
    }
    # Byte-Listen dezimal und binaer
    foreach ($m in $script:RxDezKand.Matches($Text)) {
        $z = @($m.Value -split '\s*,\s*' | ForEach-Object { [int]$_ })
        if (@($z | Where-Object { $_ -gt 255 }).Count -gt 0) { continue }
        Add-Kodiert $sp $m.Index $m.Length ([byte[]]$z) 'Byte-Liste' $Tiefe
    }
    foreach ($m in $script:RxBinKand.Matches($Text)) {
        $z = @($m.Value -split '[ ,]+' | ForEach-Object { [Convert]::ToByte($_, 2) })
        Add-Kodiert $sp $m.Index $m.Length ([byte[]]$z) 'Binaer' $Tiefe
    }
    # Base32
    foreach ($m in $script:RxB32Kand.Matches($Text)) {
        $b = ConvertFrom-Base32 $m.Value
        if ($b) { Add-Kodiert $sp $m.Index $m.Length $b 'Base32' $Tiefe }
    }
    # Ascii85 / Base85
    foreach ($m in $script:RxA85Kand.Matches($Text)) {
        $b = ConvertFrom-Base85 $m.Groups[1].Value '!"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu' $true
        if ($b) { Add-Kodiert $sp $m.Index $m.Length $b 'Ascii85' $Tiefe }
    }
    foreach ($m in $script:RxB85Kand.Matches($Text)) {
        if (([regex]::Matches($m.Value, '[!#$%&()*+;<=>?@^`{|}~]')).Count -lt 2) { continue }
        $b = ConvertFrom-Base85 $m.Value '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~' $false
        if ($b) { Add-Kodiert $sp $m.Index $m.Length $b 'Base85' $Tiefe }
    }
    # uuencode
    foreach ($m in $script:RxUUKand.Matches($Text)) {
        $b = ConvertFrom-UU $m.Groups[1].Value
        if ($b) { Add-Kodiert $sp $m.Index $m.Length $b 'uuencode' $Tiefe }
    }
    # Escapes mitten im Text (%41, A, \x41, &#65;): Text entschluesselt nochmal pruefen, Fundstellen zurueckrechnen
    $esc = $script:RxEscape.Matches($Text)
    if ($esc.Count -ge 1 -and $esc.Count -le 5000) {
        $sb = New-Object System.Text.StringBuilder
        $pos = 0; $k = 0; $extra = 0
        $vi = New-Object int[] $esc.Count; $ex = New-Object int[] $esc.Count
        foreach ($m in $esc) {
            [void]$sb.Append($Text, $pos, $m.Index - $pos)
            $e = $m.Value; $code = 63
            try {
                if ($e[0] -eq '%') { $code = [Convert]::ToInt32($e.Substring(1), 16) }
                elseif ($e[0] -eq '\') { $code = [Convert]::ToInt32($e.Substring(2), 16) }
                elseif ($e -match '^&#[xX]') { $code = [Convert]::ToInt32($e.Substring(3, $e.Length - 4), 16) }
                elseif ($e.StartsWith('&#')) { $code = [int]$e.Substring(2, $e.Length - 3) }
                elseif ($e -eq '&amp;') { $code = 38 } elseif ($e -eq '&lt;') { $code = 60 } elseif ($e -eq '&gt;') { $code = 62 } elseif ($e -eq '&quot;') { $code = 34 } else { $code = 39 }
            } catch { $code = 63 }
            if ($code -lt 9 -or $code -gt 65535) { $code = 63 }
            $vi[$k] = $sb.Length; $extra += ($m.Length - 1); $ex[$k] = $extra; $k++
            [void]$sb.Append([char]$code)
            $pos = $m.Index + $m.Length
        }
        [void]$sb.Append($Text, $pos, $Text.Length - $pos)
        foreach ($x in (Find-Secrets $sb.ToString() ($Tiefe + 1))) {
            $a = 0; $b = 0; $drin = $false; $ende = $x.S + $x.L
            for ($i = 0; $i -lt $k; $i++) {
                if ($vi[$i] -ge $ende) { break }
                if ($vi[$i] -lt $x.S) { $a = $ex[$i] }
                $b = $ex[$i]
                if ($vi[$i] -ge ($x.S - 40)) { $drin = $true }
            }
            if (-not $drin) { continue }
            $qs = $x.S + $a; $qe = $x.S + $x.L + $b
            # haengt der Treffer an einer Kette von Escapes (komplett kodierter Text), die ganze Kette schwaerzen
            $mv = $script:RxEscLaufVor.Match($Text.Substring(0, $qs));  if ($mv.Success) { $qs = $mv.Index }
            $mn = $script:RxEscLaufNach.Match($Text, $qe);              if ($mn.Success -and $mn.Index -eq $qe) { $qe += $mn.Length }
            Add-Span $sp $qs ($qe - $qs) ("Escaped: " + $x.N)
        }
    }
    # ROT13 und rueckwaerts geschriebener Text (nur feste Formate und Stichwort+Wert)
    if ($Tiefe -eq 0 -and $Text.Length -le 20000) {
        $ch = $Text.ToCharArray()
        for ($i = 0; $i -lt $ch.Length; $i++) {
            $c = [int]$ch[$i]
            if ($c -ge 97 -and $c -le 122) { $ch[$i] = [char](97 + (($c - 84) % 26)) }
            elseif ($c -ge 65 -and $c -le 90) { $ch[$i] = [char](65 + (($c - 52) % 26)) }
        }
        foreach ($x in (Find-Secrets (New-Object string (, $ch)) 9 $true)) { Add-Span $sp $x.S $x.L ("ROT13: " + $x.N) }
        $ch = $Text.ToCharArray(); [array]::Reverse($ch)
        foreach ($x in (Find-Secrets (New-Object string (, $ch)) 9 $true)) { Add-Span $sp ($Text.Length - $x.S - $x.L) $x.L ("Rueckwaerts: " + $x.N) }
    }
}

function Test-Luhn([string]$z) {
    $sum = 0; $alt = $false
    for ($i = $z.Length - 1; $i -ge 0; $i--) {
        $d = [int][string]$z[$i]
        if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }
        $sum += $d; $alt = -not $alt
    }
    return ($sum % 10 -eq 0)
}

# Ist der Schluesselname wirklich ein Secret-Feld?  (clientSecret ja, compass / max_tokens / token_url nein)
function Test-Schluessel([string]$k) {
    $k = $k.Trim('-', '_', '.', ' ', ':')
    if (-not $k) { return $false }
    $k = [regex]::Replace($k, '(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', '_')
    $n = [regex]::Replace($k.ToLower(), '[.\-:]+', '_')
    $w = @($n.Split('_') | Where-Object { $_ })
    if ($w.Count -eq 0) { return $false }
    if ($script:KeyNein.Contains($w[-1]) -and $n -notmatch 'webhook_url|session_id|dsn') { return $false }
    return $script:RxKeyJa.IsMatch($n)
}

# Sieht der Wert nach echtem Secret aus?  (kein Platzhalter, keine Variable, kein Code)
function Test-Wert([string]$v, [bool]$BuchstabenOk) {
    if (-not $v) { return $false }
    $v = $v.Trim()
    if ($v.Length -lt 3) { return $false }
    # Variablen, Platzhalter, Code - aber keine Passwoerter, die bloss mit einem Sonderzeichen beginnen
    if ($v -match '^\$\{?[A-Za-z_][\w:.]*\}?$|^\$\(|^%[A-Za-z_]\w*%$|^\{.*\}$|^<.*>$|^\[.*\]$|^\(.*\)$|^=>|^==|^[\[<{(][A-Za-z\u00C0-\u017F _-]*[\]>})]?$|^\*+$|^#+$|^![A-Za-z]+(?:\s|$)|^@[A-Za-z_][\w.]*$') { return $false }
    if ($v -match '^[A-Za-z_][A-Za-z_.]{2,}\(|\$\{|\$\(|\{\{|\}\}|^\w+\[[^\]]*\]$|^(?:[A-Za-z_][\w.]*)?(?:\(\)|\[\]|\{\})[;,]?$') { return $false }
    if ($v.IndexOfAny([char[]]'(){}') -ge 0 -and (($v -replace '[(){}\[\];:,.<>]', '') -match '^[A-Za-z_\u00C0-\u017F]*$')) { return $false }
    if ($v -cmatch '^(?:[A-Z][a-z]+-[A-Z][A-Za-z]+|\[[\w.]+\]::\w+)$') { return $false }    # Cmdlet / .NET-Aufruf
    if ($script:WertNein.Contains($v.ToLower().TrimEnd('.', ',', ';', ':', '!', '?'))) { return $false }
    if ($script:RxPlatzhalter.IsMatch($v)) { return $false }
    if ($v -match '^\d+\*\w+$') { return $false }
    if ($script:RxCode.IsMatch($v)) {
        # obj.eigenschaft ist Code - ausser die Teile sind erkennbar Zufall (kaum Kleinbuchstaben-Woerter)
        $lw = 0; foreach ($mm in [regex]::Matches($v, '[a-z]{3,}')) { $lw += $mm.Length }
        if (-not ($v.Length -ge 12 -and $v -cmatch '[a-z]' -and $v -cmatch '[A-Z].*[A-Z].*[A-Z]' -and ($lw / $v.Length) -lt 0.3 -and $v -notmatch '::|^(?:os|process|env|secrets|vars|config|settings|self|this|args|params|request|req|response|res|data|options|opts)\b')) { return $false }
    }
    if (-not $BuchstabenOk -and $v -cmatch '^(?:[A-Z]?[a-z\u00C0-\u017F]+|[A-Z\u00C0-\u017F]+|(?:[A-Z][a-z]+){2,}|[a-z]+(?:[A-Z][a-z]+)+)(?:[_-](?:[A-Z]?[a-z]+|[A-Z]+))*[.,;:!?]?$') { return $false }
    return $true
}

function Get-WertLaenge([string]$v) {
    $n = $v.Length
    $m = $script:RxWertEnde.Match($v)
    if ($m.Success -and $m.Index -ge 1) { $n = $m.Index }
    $w = $v.Substring(0, $n)
    while ($w.Length -gt 1 -and ')]}'.IndexOf($w[$w.Length - 1]) -ge 0) {      # schliessende Klammer ohne oeffnende gehoert zum Code drumherum
        $auf = '([{'[')]}'.IndexOf($w[$w.Length - 1])]
        if ($w.IndexOf($auf) -ge 0) { break }
        $w = $w.Substring(0, $w.Length - 1)
    }
    return $w.TrimEnd(',', ';').Length
}

function Add-Span($Liste, [int]$Start, [int]$Laenge, [string]$Name) {
    if ($Laenge -gt 0) { [void]$Liste.Add([pscustomobject]@{ S = $Start; L = $Laenge; N = $Name }) }
}

function Find-Secrets([string]$Text, [int]$Tiefe = 0, [bool]$NurFest = $false) {
    $sp = New-Object System.Collections.ArrayList

    # 1) eigene Regeltabelle
    foreach ($r in $script:Regeln) {
        if ($NurFest -and -not $r.Lit) { continue }
        try {
            foreach ($m in $r.Rx.Matches($Text)) {
                $g = $m.Groups['s']
                if (-not $g.Success) { $g = $m }
                if ($r.Art -eq 'W' -and -not (Test-Wert $g.Value $true))  { continue }
                if ($r.Art -eq 'B' -and -not (Test-Wert $g.Value $false)) { continue }
                Add-Span $sp $g.Index $g.Length $r.Name
            }
        } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    }

    # 2) Stichwort + Wert
    try {
        foreach ($m in $script:RxKv.Matches($Text)) {
            if (-not (Test-Schluessel $m.Groups['k'].Value)) { continue }
            $g = $m.Groups['s']
            $quoted = $m.Groups['q'].Success
            $eng = ($m.Groups['op'].Value -eq '=' -and $m.Groups['pre'].Length -eq 0 -and $m.Groups['post'].Length -eq 0)
            $ws = $g.Index; $wl = $g.Length; $wert = $g.Value
            if (-not $quoted) {
                # Wert endet am Trenner zum naechsten Feld (;key= &key= ,key=), nicht an jedem Sonderzeichen: Passwoerter enthalten & ; ,
                $wl = Get-WertLaenge $wert
                if ($wl -lt 3) { continue }
                $wert = $wert.Substring(0, $wl)
                $kl = [regex]::Match($wert, '^\{([^{}\s]{6,})\}$')
                if ($kl.Success -and $kl.Groups[1].Value -match '[^A-Za-z_.:-]') { $ws++; $wl -= 2; $wert = $kl.Groups[1].Value }   # ODBC: Pwd={...}
            }
            if (-not (Test-Wert $wert ($quoted -or $eng))) { continue }
            Add-Span $sp $ws $wl 'Stichwort+Wert'
        }
        foreach ($m in $script:RxFlag.Matches($Text)) {
            if (-not (Test-Schluessel $m.Groups['k'].Value)) { continue }
            $g = $m.Groups['s']
            if (-not (Test-Wert $g.Value $true)) { continue }
            Add-Span $sp $g.Index $g.Length 'Schalter+Wert'
        }
        foreach ($m in $script:RxXml.Matches($Text)) {
            if (-not (Test-Schluessel $m.Groups['k'].Value)) { continue }
            $g = $m.Groups['s']
            if (-not (Test-Wert $g.Value $true)) { continue }
            Add-Span $sp $g.Index $g.Length 'XML-Feld'
        }
    } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }

    if (-not $NurFest) {
    # 3) Kreditkarten (mit Luhn-Pruefung)
    foreach ($m in $script:RxKarte.Matches($Text)) {
        $z = $m.Value -replace '[ -]', ''
        if ($script:RxKartenTyp.IsMatch($z) -and (Test-Luhn $z)) { Add-Span $sp $m.Index $m.Length 'Kreditkarte' }
    }

    # 4) Entropie: lange Zufallsstrings ohne bekanntes Format (nicht in URLs, nicht in oeffentlichen Zertifikaten/SSH-Public-Keys)
    $urls = @($script:RxUrl.Matches($Text))
    $oeff = @($script:RxOeffentlich.Matches($Text))
    foreach ($m in $script:RxEntropie.Matches($Text)) {
        $v = $m.Value
        if ($v -match '^sha\d{1,3}-') { continue }
        $form = ($v -cmatch '^(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)$')      # 32- bzw. 64-Byte-Schluessel (Azure Storage, Service Bus, WireGuard ...)
        if (-not $form) {
            if ($v.IndexOf('/') -ge 0) {
                $seg  = @($v.TrimEnd('=') -split '/' | Where-Object { $_.Length -ge 3 })
                $wort = @($seg | Where-Object { $_ -cmatch '^(?:[A-Za-z][a-z]+(?:[A-Z][a-z]+)*|[a-z0-9_+-]+|[A-Z0-9_+-]+)$' })
                if ($seg.Count -eq 0 -or ($wort.Count * 2) -ge $seg.Count) { continue }     # Pfade
                if (-not (Test-Zufall ($v -replace '[/+]', ''))) { continue }
            } elseif (-not (Test-Zufall $v)) { continue }
        }
        if (Test-Bereich $urls $m.Index) { continue }
        if (Test-Bereich $oeff $m.Index) { continue }
        $davor = $Text.Substring([math]::Max(0, $m.Index - 12), [math]::Min(12, $m.Index))
        if ($davor -match '(?i)sha\d{1,3}[-:=]\s*$|integrity\W*$|base64,$|\\$') { continue }
        $ende = $m.Index + $m.Length
        $nach = $Text.Substring($ende, [math]::Min(8, $Text.Length - $ende))
        if ($nach -cmatch '^\.[a-z0-9]{2,5}(?![A-Za-z0-9_.-])') { continue }                # Dateiname mit Endung
        Add-Span $sp $m.Index $m.Length 'Zufallsstring'
    }

    # 4b) Hex-Schluessel ab 32 Zeichen ohne Hash-/ID-Kontext (API-Keys vieler Dienste sind reines Hex)
    foreach ($m in $script:RxHexNackt.Matches($Text)) {
        $v = $m.Value
        if (($v -cmatch '[a-f]' -and $v -cmatch '[A-F]') -or $v -match '^\d+$') { continue }
        if ((Get-Entropie $v) -lt 3.0) { continue }
        if ((Test-Bereich $urls $m.Index) -or (Test-Bereich $oeff $m.Index)) { continue }
        $davor = $Text.Substring([math]::Max(0, $m.Index - 48), [math]::Min(48, $m.Index))
        if ($script:RxHashKontext.IsMatch($davor) -or $davor -match '(?i)sha-?\d|md5|hash|checksum|digest|pr\S{1,2}fsumme') { continue }
        $ende = $m.Index + $m.Length
        $nach = $Text.Substring($ende, [math]::Min(60, $Text.Length - $ende))
        if ($nach -match '^[ \t]+\*?[\w.\\/:-]+\.\w{1,5}(?:\s|$)') { continue }             # Ausgabe von md5sum/sha256sum: Hash + Dateiname
        Add-Span $sp $m.Index $m.Length 'Hex-Schluessel'
    }

    # 4c) Zufallsstrings mit Sonderzeichen (alte Entra-Client-Secrets, generierte Passwoerter)
    foreach ($m in $script:RxSymbol.Matches($Text)) {
        $v = $m.Value
        if ($v -cnotmatch '[a-z]' -or $v -cnotmatch '[A-Z]') { continue }
        $sym = ([regex]::Matches($v, '[^A-Za-z0-9]')).Count
        $zif = ([regex]::Matches($v, '\d')).Count
        if ($sym -lt 1 -or ($zif -lt 2 -and $sym -lt 2) -or ($zif -lt 1 -and $sym -lt 4)) { continue }
        if ($v -cmatch '\.[a-z]{2,4}$') { continue }                                        # Dateiname
        if ($v -match '://|=>|->|::|//|@[\w-]+\.[a-z]{2,}$|^\w+=\w+$') { continue }
        $wort = $false                                                                      # enthaelt Woerter?
        foreach ($l in [regex]::Matches($v, '[A-Z]?[a-z]{5,}|[A-Z]{6,}')) {
            $pp = [regex]::Matches($l.Value, '(?=([A-Za-z]{2}))'); $g = 0
            foreach ($q in $pp) { if ($script:Bigramme.Contains($q.Groups[1].Value.ToLowerInvariant())) { $g++ } }
            if (($g / $pp.Count) -ge 0.6) { $wort = $true; break }
        }
        if ($wort) { continue }
        if ((Get-Entropie $v) -lt 4.0) { continue }
        if ((Test-Bereich $urls $m.Index) -or (Test-Bereich $oeff $m.Index)) { continue }
        Add-Span $sp $m.Index $m.Length 'Zufallsstring (Sonderzeichen)'
    }
    }

    # 5) gitleaks-Regeln (nur wenn ein Keyword der Regel im Text vorkommt)
    if (-not $NurFest -and $script:GlRegeln.Count -gt 0 -and $Text.Length -le 300000) {   # bei Riesentexten nur die eigenen Regeln, sonst dauert es zu lange
        $klein = $Text.ToLowerInvariant()
        foreach ($r in $script:GlRegeln) {
            $ok = ($r.Kw.Count -eq 0)
            foreach ($k in $r.Kw) { if ($klein.Contains($k)) { $ok = $true; break } }
            if (-not $ok) { continue }
            try {
                foreach ($m in $r.Rx.Matches($Text)) {
                    $g = $m
                    if ($r.Grp -gt 0 -and $m.Groups[$r.Grp].Success) { $g = $m.Groups[$r.Grp] }
                    elseif ($m.Groups.Count -gt 1) { for ($i = 1; $i -lt $m.Groups.Count; $i++) { if ($m.Groups[$i].Success -and $m.Groups[$i].Length -gt 0) { $g = $m.Groups[$i]; break } } }
                    if ($r.Ent -gt 0 -and (Get-Entropie $g.Value) -lt $r.Ent) { continue }
                    if (-not (Test-Wert $g.Value $true)) { continue }
                    Add-Span $sp $g.Index $g.Length $r.Name
                }
            } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
        }
    }

    if (-not $NurFest) {
    # 6) gemerkte Secrets - auch in Variationen (gross/klein, URL-kodiert, Base64, Hex, escaped, umgebrochen, Bruchstueck)
    $varianten = ($Text.Length -le 100000)
    foreach ($g in $script:Gemerkt) {
        $liste = if ($varianten) { $g.V } else { @($g.S) }
        foreach ($v in $liste) {
            $i = $Text.IndexOf($v, [StringComparison]::OrdinalIgnoreCase)
            while ($i -ge 0) {
                Add-Span $sp $i $v.Length 'Gemerktes Secret'
                $i = $Text.IndexOf($v, $i + $v.Length, [StringComparison]::OrdinalIgnoreCase)
            }
        }
        if ($varianten -and $g.Rx -and $Text.IndexOf($g.S.Substring(0, 3), [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            try { foreach ($m in $g.Rx.Matches($Text)) { Add-Span $sp $m.Index $m.Length 'Gemerktes Secret (umgebrochen)' } }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
        }
    }
    }
    if (-not $NurFest) {
        # 7) Kubernetes-Secret: alle Werte unter data:/stringData:
        if ($Text -match '(?m)^\s*kind:\s*Secret\b') {
            foreach ($bl in [regex]::Matches($Text, '(?m)^(?<e>[ \t]*)(?:data|stringData):[ \t]*\r?\n(?<b>(?:\k<e>[ \t]+\S.*(?:\r?\n|$))+)')) {
                foreach ($m in [regex]::Matches($bl.Groups['b'].Value, '(?m)^[ \t]+[\w.-]+:[ \t]*(?<q>["'']?)(?<s>[^\s"''].*?)\k<q>[ \t]*\r?$')) {
                    Add-Span $sp ($bl.Groups['b'].Index + $m.Groups['s'].Index) $m.Groups['s'].Length 'Kubernetes-Secret'
                }
            }
        }
        # 8) kodierte / gepackte Inhalte
        if ($Tiefe -lt 3 -and $Text.Length -le 200000) {
            try { Find-Kodiert $sp $Text $Tiefe } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
        }
    }
    return ,$sp
}

function Merge-Spans($Spans) {
    $out = New-Object System.Collections.ArrayList
    foreach ($s in ($Spans | Sort-Object S, @{ Expression = 'L'; Descending = $true })) {
        if ($out.Count -gt 0) {
            $l = $out[$out.Count - 1]
            if ($s.S -le ($l.S + $l.L)) {
                $ende = [math]::Max($l.S + $l.L, $s.S + $s.L)
                $l.L = $ende - $l.S
                if ($l.N -notlike "*$($s.N)*" -and $l.N.Length -lt 80) { $l.N = "$($l.N), $($s.N)" }
                continue
            }
        }
        [void]$out.Add([pscustomobject]@{ S = $s.S; L = $s.L; N = $s.N })
    }
    return ,$out
}

# Alle Schreibweisen, in denen ein bekanntes Secret spaeter wieder auftauchen kann
function Get-Varianten([string]$s) {
    $v = New-Object 'System.Collections.Generic.List[string]'
    $v.Add($s)
    try { $v.Add([uri]::EscapeDataString($s)); $v.Add([System.Net.WebUtility]::UrlEncode($s)) } catch { }
    try {
        $b = [Text.Encoding]::UTF8.GetBytes($s)
        $b64 = [Convert]::ToBase64String($b)
        $v.Add($b64); $v.Add($b64.TrimEnd('=')); $v.Add($b64.Replace('+', '-').Replace('/', '_').TrimEnd('='))
        $v.Add(([BitConverter]::ToString($b)).Replace('-', ''))
        $v.Add([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s)))      # UTF-16, z.B. -EncodedCommand
    } catch { }
    $v.Add($s.Replace('\', '\\').Replace('"', '\"'))                                   # JSON / C-String
    $v.Add($s.Replace('\', '\\').Replace("'", "\'"))
    $v.Add($s.Replace("'", "''"))                                                      # PowerShell / SQL
    $v.Add($s.Replace('"', '""'))                                                      # CSV / VBS
    $v.Add($s.Replace('`', '``').Replace('$', '`$').Replace('"', '`"'))                # PowerShell "..."
    $v.Add($s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;'))   # XML / HTML
    $v.Add($s.Replace('/', '\/'))                                                      # JSON mit escaptem Slash
    $v.Add($s.Replace('%', '%%'))                                                      # Batch
    if ($s.Length -ge 24) { $v.Add($s.Substring(0, 16)); $v.Add($s.Substring($s.Length - 16)) }   # Bruchstuecke
    return @($v | Where-Object { $_.Length -ge 8 } | Select-Object -Unique)
}

function Add-Gemerkt([string]$s) {
    $s = $s.Trim()
    if ($s.Length -lt 8 -or $s.Length -gt 1024) { return }
    foreach ($g in $script:Gemerkt) { if ($g.S -ceq $s) { return } }
    $rx = $null
    if ($s.Length -ge 20 -and $s.Length -le 200) {   # auch zerstueckelt (Zeilenumbruch, "abc" + "def", Backslash-Fortsetzung)
        try {
            $muster = (($s.ToCharArray() | ForEach-Object { [regex]::Escape([string]$_) }) -join '[ \t\r\n"''+\\]{0,3}')
            $rx = New-Object regex -ArgumentList @($muster, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [timespan]::FromMilliseconds(300))
        } catch { $rx = $null }
    }
    $script:Gemerkt.Add([pscustomobject]@{ S = $s; V = (Get-Varianten $s); Rx = $rx })
    if ($script:Gemerkt.Count -gt 100) { $script:Gemerkt.RemoveAt(0) }
}

<#  Kern: Text rein, geschwaerzter Text raus. Alles Erkannte wird ersetzt, auch ein einzeln kopiertes Secret.
    Rueckgabe: Text, Anzahl, Namen (Regeln), Nackt (= der Text bestand NUR aus dem Secret)  #>
function Protect-Text([string]$Text) {
    $res = [pscustomobject]@{ Text = $Text; Anzahl = 0; Namen = @(); Nackt = $false; Geaendert = $false }
    if (-not $Text -or $Text.Length -gt $script:MaxZeichen) { return $res }
    $roh = Find-Secrets $Text
    if ($roh.Count -eq 0) { return $res }
    $sp = Merge-Spans $roh
    # Reste direkt neben einem Treffer (Signatur, Endstueck, Praefix) gehoeren zum selben Token: Treffer ausweiten
    foreach ($x in $sp) {
        if ($x.L -lt 8) { continue }
        while ($x.S -gt 0 -and $Text[$x.S - 1] -match '[A-Za-z0-9_.~-]') {
            if ($Text.Substring([math]::Max(0, $x.S - 6), [math]::Min(6, $x.S)) -match '(?:%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})$') { break }
            $x.S--; $x.L++
        }
        while (($x.S + $x.L) -lt $Text.Length -and ($Text[$x.S + $x.L] -match '[A-Za-z0-9_~+-]' -or ($Text[$x.S + $x.L] -eq '.' -and ($x.S + $x.L + 1) -lt $Text.Length -and $Text[$x.S + $x.L + 1] -match '[A-Za-z0-9_-]'))) { $x.L++ }
    }
    # Zweiteilige Secrets (id:secret, SAP-Form a!b|c): Rest hinter : ! | $ mitnehmen, wenn er wie ein Token aussieht
    foreach ($x in $sp) {
        if ($x.L -lt 16) { continue }
        for ($k = 0; $k -lt 4; $k++) {
            $e = $x.S + $x.L
            if ($e -ge $Text.Length -or $Text[$e] -notmatch '[:!|$]') { break }
            $m2 = [regex]::Match($Text.Substring($e + 1, [math]::Min(200, $Text.Length - $e - 1)), '^[A-Za-z0-9_~+.!-]{4,}')
            if (-not $m2.Success -or $m2.Value -notmatch '\d') { break }
            $x.L += 1 + $m2.Length
        }
    }
    $sp = Merge-Spans $sp
    $res.Anzahl = $sp.Count
    $res.Namen  = @($sp | ForEach-Object { $_.N } | Select-Object -Unique)

    if ($sp.Count -eq 1) {
        $rest = $Text.Remove($sp[0].S, $sp[0].L).Trim().Trim('"', "'", '`').Trim()
        if ($rest.Length -eq 0) { $res.Nackt = $true }
    }
    # Jedes erkannte Secret merken, damit es spaeter auch in anderer Schreibweise / allein erkannt wird
    foreach ($x in $sp) { if ($x.L -ge 8 -and $x.L -le 512) { Add-Gemerkt ($Text.Substring($x.S, $x.L)) } }
    if ($res.Nackt) { Add-Gemerkt ($Text.Trim().Trim('"', "'", '`')) }

    $sb = New-Object System.Text.StringBuilder $Text
    for ($i = $sp.Count - 1; $i -ge 0; $i--) {
        [void]$sb.Remove($sp[$i].S, $sp[$i].L)
        [void]$sb.Insert($sp[$i].S, $script:Marke)
    }
    $res.Text = $sb.ToString()
    $res.Geaendert = $true
    return $res
}

function Initialize-Regeln {
    $script:Regeln.Clear()
    Import-RegelTabelle $RegelTabelle
    Import-Eigene
    [void](Import-Gitleaks $script:GlPfad)
}

function Update-Gitleaks {
    if (-not (Test-Path -LiteralPath $script:DatenDir)) { [void](New-Item -ItemType Directory -Path $script:DatenDir -Force) }
    $tmp = "$($script:GlPfad).neu"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $script:GlUrl -OutFile $tmp -UseBasicParsing
    if ((Get-Item -LiteralPath $tmp).Length -lt 20000) { Remove-Item -LiteralPath $tmp -Force; throw "Download sieht kaputt aus." }
    Move-Item -LiteralPath $tmp -Destination $script:GlPfad -Force
    return (Import-Gitleaks $script:GlPfad)
}

Initialize-Regeln

# =====================================================================================================
#  KOMMANDOZEILEN-MODI
# =====================================================================================================
if ($RegelnAktualisieren) {
    $n = Update-Gitleaks
    Write-Host "gitleaks-Regeln geladen: $n" -ForegroundColor Green
    return
}

if ($Pruefe) {
    $t = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Pruefe))
    $r = Protect-Text $t
    Write-Host "Treffer: $($r.Anzahl)  [$($r.Namen -join ' | ')]" -ForegroundColor Cyan
    Write-Output $r.Text
    return
}

if ($SelbstTest) {
    # Alle Test-Secrets sind erfunden und werden zusammengesetzt, damit kein Scanner auf diese Datei anspringt.
    $z40 = 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6oR9u'
    $hex = '9f86d081884c7d659a2feaa0c55ad015'
    $soll = @(
        @('rclone-Leak',        ('Failed to create file system for ":webdav,url=''https://homeserver:8443/remote.php/dav/files/root'',vendor=nextcloud,user=root,pass=' + '52swxwoCk5WokDVtAJXWMxquQ1TpQPlkfwb0brmVOP_NYg' + ':Jellyfin/Filme": read metadata failed'), '52swx'),
        @('Entra-Secret',       ('az login --service-principal -u 11111111-2222-3333-4444-555555555555 --tenant contoso -p ' + 'abc8Q~' + 'dEfGhIjKlMnOpQrStUvWxYz0123456789a'), '8Q~'),
        @('Entra in JSON',      ('{ "clientId": "11111111-2222-3333-4444-555555555555", "clientSecret": "' + 'xYz7Q~' + 'AbCdEfGhIjKlMnOpQrStUvWxYz012345_.' + '" }'), '7Q~'),
        @('Storage-ConnString', ('DefaultEndpointsProtocol=https;AccountName=meinstorage;AccountKey=' + ($z40 + $z40 + 'aB3dE6') + '==;EndpointSuffix=core.windows.net'), 'aB3dE6gH'),
        @('Flow-Trigger-URL',   ('POST https://prod-12.westeurope.logic.azure.com:443/workflows/abc123/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=' + 'Xk3_' + $z40), 'Xk3_'),
        @('PnP-Befehl',         ('Connect-PnPOnline -Url https://contoso.sharepoint.com -ClientId abc -ClientSecret "' + 'Sup3r' + 'Geheim!42' + '"'), 'Sup3rGeheim'),
        @('SecureString',       ('$sec = ConvertTo-SecureString "' + 'Winter' + '2026!' + '" -AsPlainText -Force'), 'Winter2026'),
        @('JWT',                ('Authorization: Bearer ' + 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' + '.' + 'eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20ifQ' + '.' + 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'), 'eyJhbGci'),
        @('SharePoint-Cookie',  ('Cookie: FedAuth=' + '77u/PD94bWwgdmVyc2lvbj0iMS4wIj8+' + '; rtFa=' + $z40), '77u/'),
        @('GitHub-PAT',         ('git remote set-url origin https://user:' + 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' + '@github.com/user/projekt.git'), 'ghp_'),
        @('Gemini-Key',         ('const genAI = new GoogleGenerativeAI("' + 'AIza' + 'SyD3mo-K3y_0123456789abcdefghijklmno' + '");'), 'AIzaSy'),
        @('OpenAI-Key .env',    ('OPENAI_API_KEY=' + 'sk-proj-' + $z40), 'sk-proj'),
        @('Anthropic-Key',      ('export ANTHROPIC_API_KEY="' + 'sk-ant-api03-' + $z40 + '"'), 'sk-ant'),
        @('HF-Token',           ('huggingface-cli login --token ' + 'hf_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz01234567'), 'hf_Ab'),
        @('Nextcloud-App-PW',   ('Benutzer: max  App-Passwort: ' + 'aB3dE-fG6hJ-kL9mN-pQ2rS-tU5vW'), 'aB3dE-'),
        @('Jellyfin-Key',       ('curl "http://homeserver:8096/Users?api_key=' + $hex + '"'), $hex),
        @('Emby-Header',        ('X-Emby-Token: ' + $hex), $hex),
        @('Tailscale',          ('tailscale up --authkey ' + 'tskey-auth-' + 'kAbCdE1CNTRL-' + 'AbCdEfGhIjKlMnOpQrStUvWx'), 'tskey'),
        @('HenrikDev',          ('headers: { Authorization: "' + 'HDEV-' + '12345678-abcd-4321-abcd-1234567890ab' + '" }'), 'HDEV-'),
        @('Private Key',        ("mein key fuer den server:`n-----BEGIN OPENSSH PRIVATE KEY-----`nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz`nc2gtZWQyNTUxOQAAACD`n-----END OPENSSH PRIVATE KEY-----"), 'b3Blbn'),
        @('Service-Account',    ('"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"'), 'MIIEvQ'),
        @('Gradle-Keystore',    ("storePassword=" + "Kaffee" + "tasse#9`nkeyAlias=upload`nkeyPassword=" + "Kaffee" + "tasse#9"), 'Kaffeetasse#9'),
        @('YAML',               ("db:`n  user: admin`n  password: " + "Tr0ub4dor" + "&3`n  port: 5432"), 'Tr0ub4dor'),
        @('DB-URL',             ('postgres://max:' + 'p4ssw0rt' + '@homeserver:5432/app'), 'p4ssw0rt'),
        @('curl -u',            ('curl.exe -k -u "max:' + 'geheim' + '123" https://homeserver:8443/'), 'geheim123'),
        @('bcrypt',             ('users: [{ name: max, password: ' + '$2a$10$' + 'N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' + ' }]'), 'N9qo8u'),
        @('WLAN netsh',         ("    Sicherheitsschluessel  : Vorhanden`n    Key Content            : " + "Sonnen" + "blume2026"), 'Sonnenblume'),
        @('XML',                ('<Credentials><Username>svc</Username><Password>' + 'Pa$$' + 'w0rd!' + '</Password></Credentials>'), 'w0rd!'),
        @('Satz',               ('ey das Passwort ist ' + 'Banane' + '#77 falls du es brauchst'), 'Banane#77'),
        @('Zufallsstring',      ('hier der key vom Kollegen: ' + 'Zk9' + $z40 + ' bitte testen'), 'Zk9aB3'),
        @('Stripe',             ('stripe listen --api-key ' + 'sk_' + 'test_' + '4eC39HqLyjWDarjtT1zdp7dc'), '4eC39'),
        @('Discord-Webhook',    ('WEBHOOK=https://discord.com/api/webhooks/123456789012345678/' + $z40 + $z40), '/aB3dE6'),
        @('Teams-Webhook',      ('Der Flow postet an https://contoso.webhook.office.com/webhookb2/' + $hex + '@' + $hex + '/IncomingWebhook/' + $hex + '/' + $hex), 'webhookb2'),
        @('Kreditkarte',        'Karte: 4111 1111 1111 1111 gueltig bis 12/29', '4111 1111'),
        @('Hex-Key im Satz',    ('Der API-Key vom Jellyfin ist uebrigens ' + $hex + ' falls du ihn brauchst'), $hex),
        @('Sonarr-XML',         ('<Config><Port>8989</Port><ApiKey>' + $hex + '</ApiKey></Config>'), $hex),
        @('Paperless-Token',    ('curl -H "Authorization: Token ' + $hex + 'a1b2c3d4" http://homeserver:8000/api/documents/'), $hex),
        @('Proxmox',            ('Authorization: PVEAPIToken=root@pam!monitoring=' + '12345678-abcd-4321-abcd-1234567890ab'), '12345678-abcd'),
        @('Beszel-UUID',        ('BESZEL_TOKEN: ' + '0a1b2c3d-1111-4222-8333-444455556666'), '0a1b2c3d'),
        @('Compose',            ("    environment:`n      - TZ=Europe/Berlin`n      - AUTHENTIK_SECRET_KEY=" + "qwertzuiop" + "asdfghjkl`n      - PG_PASS=" + "supergeheim"), 'qwertzuiopasdfghjkl'),
        @('Kleinbuchstaben-Key',('immich key: ' + 'k3j9x7q2m8v4n6b1z5c0p9w8r7t6y5u4i3o2a1s' + ' (read only)'), 'k3j9x7'),
        @('Kurzer Mix-Key',     ('pin fuer den hub: ' + 'Xk3Lm9Qw2Zr8Tn5Vb7Ya' + ' ok?'), 'Xk3Lm9'),
        @('Anthropic im Chat',  ('hier mein key ' + 'sk-ant-' + 'api03-' + $z40 + '-' + $z40 + 'AA' + ' warum geht der nicht'), 'sk-ant'),
        @('NTLM',               ('Administrator:500:aad3b435b51404eeaad3b435b51404ee:' + '31d6cfe0d16ae931b73c59d7e0c089c0' + ':::'), '31d6cfe0')
    )
    # --- Haertetest-Faelle: kodiert, gepackt, Azure-/Entra-Formate ohne Stichwort, Passwoerter mit Sonderzeichen ---
    $u8 = [System.Text.Encoding]::UTF8
    $g1 = 'client_secret=' + 'qRs8Q~' + $z40.Substring(0, 34)
    $b64 = [Convert]::ToBase64String($u8.GetBytes($g1))
    $b16 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('$p = "' + 'Sommer' + '#2026x"; Connect-Dings -Password $p -Token ' + $z40))
    $hx1 = -join ($u8.GetBytes($g1) | ForEach-Object { $_.ToString('x2') })
    $msz = New-Object System.IO.MemoryStream
    $gzs = New-Object System.IO.Compression.GZipStream ($msz, [System.IO.Compression.CompressionMode]::Compress)
    $roh = $u8.GetBytes($g1); $gzs.Write($roh, 0, $roh.Length); $gzs.Dispose()
    $gzb = [Convert]::ToBase64String($msz.ToArray())
    $pwS = 'Sup3r' + '&Geheim!42'
    $uni = -join (('password=' + 'Sommer' + '#2026x').ToCharArray() | ForEach-Object { '\u{0:x4}' -f [int]$_ })
    $key88 = $z40 + $z40 + 'aB3dE6=='
    $soll += @(
        @('Base64',             ('schau mal: ' + $b64 + ' passt das?'), $b64.Substring(0, 20)),
        @('Base64 doppelt',     [Convert]::ToBase64String($u8.GetBytes($b64)), [Convert]::ToBase64String($u8.GetBytes($b64)).Substring(0, 20)),
        @('EncodedCommand',     ('powershell -NoProfile -EncodedCommand ' + $b16), $b16.Substring(0, 24)),
        @('Hex',                $hx1, $hx1.Substring(0, 24)),
        @('Hex mit Doppelpunkt', (($hx1 -replace '(..)', '$1:').TrimEnd(':')), (($hx1 -replace '(..)', '$1:').Substring(0, 24))),
        @('gzip+Base64',        ('echo ' + $gzb + ' | base64 -d | gunzip'), $gzb.Substring(0, 20)),
        @('URL-kodiert',        ('https://example.com/login?user=admin&next=' + [uri]::EscapeDataString('password=' + $pwS)), 'Geheim'),
        @('Unicode-Escapes',    $uni, '\u0053\u006f\u006d'),
        @('ROT13',              ('Zrva Cnffjbeg vfg ' + 'Fbzzre' + '#2026k'), 'Fbzzre'),
        @('Rueckwaerts',        ('x6202#' + 'remmoS' + '=drowssap'), 'remmoS'),
        @('Hex-Key im Satz',    ('der key ' + $hex + ' geht nicht mehr'), $hex),
        @('Storage-Key nackt',  ('Wert aus dem Portal: ' + $key88), $z40),
        @('Nur Buchstaben',     ('Rz' + 'YUUDQjhygbCMEPkBlRngnfAIvfqZhPuCoA'), 'hygbCMEP'),
        @('Entra-Secret alt',   ('neues secret: ' + '8pMeLHp]MZhFGZCZ3' + 'fiBT1clq:Rl73MRSL'), 'MZhFGZCZ'),
        @('Refresh-Token',      ('0.A' + 'RwA' + $z40 + $z40 + $z40), $z40),
        @('LAPS mit Sonderz.',  ('Password            : ' + 'u3tL;Nuz]I' + '&7s,Xl'), 'Nuz]I'),
        @('ODBC Pwd={...}',     ('Driver={ODBC Driver 18 for SQL Server};Server=tcp:srv,1433;Uid=admin;Pwd={' + 'M$O~!nm' + '^4~s};Encrypt=yes;'), 'nm^4'),
        @('JDBC mit &',         ('jdbc:sqlserver://srv.database.windows.net:1433;database=db;user=admin;password=' + 'YKb&18~QNI' + '!ysX*8;encrypt=true;'), 'QNI!ysX'),
        @('Passwort mit -',     ('sshpass -p ' + "'-9YFACU7" + "bzVvv8r!' ssh root@homeserver"), 'YFACU7'),
        @('Kubernetes-Secret',  ("apiVersion: v1`nkind: Secret`nmetadata:`n  name: app`nstringData:`n  wert: " + 'geheim' + 'nis123'), 'geheimnis123'),
        @('Satz mit Umweg',     ('das root passwort vom server ist ' + 'BBcubW' + 'BAnD'), 'BBcubWBAnD'),
        @('Bicep-Parameter',    ("@secure()`nparam adminPassword string = '" + 'zYq_Ghu6' + "Bpid*jZ_2'"), 'Ghu6Bpid'),
        @('Static-Web-App',     ('deployment_token: ' + $hex + $hex + '-0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d6e7'), $hex)
    )

    $nicht = @(
        @('Prosa',              'Hi Alex, das Passwort: bitte wie besprochen im Tresor nachschauen. Der Token laeuft morgen ab.'),
        @('Code ohne Secret',   'const token = await getToken(); if (!password) { throw new Error("password required"); } const apiKey = process.env.API_KEY;'),
        @('PowerShell',         '$cred = Get-Credential; Connect-PnPOnline -Url $url -Credentials $cred; $secret = Get-Secret -Name NextcloudApp'),
        @('Platzhalter',        '$user = "DEIN-NEXTCLOUD-USER"; $pw = rclone obscure "DEIN-APP-PASSWORT"; password=<dein-passwort>'),
        @('Compass/Config',     "COMPASS_PORT=3000`nmax_tokens: 4096`ntoken_endpoint: https://login.microsoftonline.com/common/oauth2/v2.0/token`npassword_min_length=12"),
        @('GUIDs/Hashes',       'TenantId 72f988bf-86f1-41af-91ab-2d7cd011db47, Commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904, SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'),
        @('SharePoint-Link',    'https://contoso.sharepoint.com/:f:/s/Team/EqAbC1dEfGhIjKlMnOpQrStUvWxYz0123456789abcd?e=Ab1Cd2'),
        @('package-lock',       '"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="'),
        @('git/ssh',            'git clone git@github.com:user/projekt.git && ssh max@homeserver -p 22'),
        @('Ordnerpfad',         'C:\Users\max\Desktop\Rips\HD\The Hobbit An Unexpected Journey (2012) [tmdbid-49051] [1080p].mkv'),
        @('Fehlermeldung',      'System.UnauthorizedAccessException: Access token validation failure. Invalid audience. at Microsoft.Graph.HttpProvider'),
        @('Docker-Image/Tags',  'ghcr.io/immich-app/immich-server:v1.120.1 jellyfin/jellyfin:10.10.3 lscr.io/linuxserver/sonarr:4.0.10.2544-ls257'),
        @('Token+GUID harmlos', 'Die App-Registrierung (client_id 11111111-2222-3333-4444-555555555555) braucht ein neues Secret, Tenant 72f988bf-86f1-41af-91ab-2d7cd011db47.'),
        @('Commit mit token',   'commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904 fix: token refresh in auth middleware'),
        @('Dateinamen',         'backup-2026-11-16-homeserver-nextcloud-data-full-0001.tar.gz und IMG_20261116_184523_processed_final_v2.jpg'),
        @('Lange Bezeichner',   'handleClipboardSequenceNumberChanged2 microsoft-powershell-secretmanagement-module-v1 x86_64-pc-windows-msvc-toolchain-1.82.0'),
        @('HTML-Formular',      '<input type="password" name="password" autocomplete="current-password" required>')
    )
    $ok = 0; $fail = 0
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
    Write-Host ""
    Write-Host "  clipguard selbsttest" -ForegroundColor Magenta
    Write-Host ("  {0} eigene + {1} gitleaks-Regeln`n" -f $script:Regeln.Count, $script:GlRegeln.Count) -ForegroundColor DarkGray
    $nicht += @(
        @('git log',            "commit 3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f (HEAD -> main)`nAuthor: max`n    fix: Pfad korrigiert"),
        @('md5sum/Get-FileHash', "d41d8cd98f00b204e9800998ecf8427e  datei.iso`nSHA256          E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855       C:\Users\max\Downloads\setup.exe"),
        @('Dateiname',          'Bitte schick mir die Datei Quartalsbericht_Finanzen_2026_Q3_final_ueberarbeitet_v2.xlsx bis morgen.'),
        @('SSH-Public-Key',     'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbL0m9x3Yz1qVf8n2hQk4tR7wPj6sXc5dAe0uBvN1oL max@pc'),
        @('Zertifikat',         "-----BEGIN CERTIFICATE-----`nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ`nRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD`n-----END CERTIFICATE-----"),
        @('Konstanten',         "TAKEN_FROM_ARGUMENT4U = -4   # num bytes`nMAX_CONCURRENT_UPLOAD_CONNECTIONS_PER_HOST = 12"),
        @('TypeScript',         'function validatePassword(password: string): boolean { return password.length >= 12; }'),
        @('Pfade',              'src/components/Dashboard/WidgetContainer/WidgetContainerHeaderActions.tsx und C:\Users\max\AppData\Local\Programs\Microsoft VS Code\resources'),
        @('Lange Bezeichner',   'getElementsByClassNameAndAttributeValueFromDocumentFragment Microsoft.Graph.Authentication.Commands.ConnectMgGraphCommandExtensionsInternal'),
        @('Azure-IDs',          'Tenant-ID: 72f988bf-86f1-41af-91ab-2d7cd011db47 /subscriptions/0b1f6471-1bf0-4dda-aec3-cb9272f09590/resourceGroups/rg-prod'),
        @('Byte-Liste harmlos', '[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] und 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08'),
        @('Base64 harmlos',     'SGVsbG8gV2VsdA==')
    )
    foreach ($t in $soll) {
        $script:Gemerkt.Clear()
        $r = Protect-Text $t[1]
        if ($r.Geaendert -and -not $r.Text.Contains($t[2])) { $ok++; Write-Host ("  +     {0,-20} {1}" -f $t[0], ($r.Namen -join ' | ')) -ForegroundColor Green }
        else { $fail++; Write-Host ("  FEHLT {0,-20} -> {1}" -f $t[0], $r.Text) -ForegroundColor Red }
    }
    Write-Host ""
    foreach ($t in $nicht) {
        $script:Gemerkt.Clear()
        $r = Protect-Text $t[1]
        if (-not $r.Geaendert) { $ok++; Write-Host ("  +     {0,-20} bleibt unveraendert" -f $t[0]) -ForegroundColor Green }
        else { $fail++; Write-Host ("  FALSCH {0,-19} [{1}] -> {2}" -f $t[0], ($r.Namen -join ' | '), $r.Text) -ForegroundColor Yellow }
    }
    Write-Host ""
    # --- Einzeln kopierte Secrets: werden jetzt IMMER geschwaerzt (das Original liegt in Win+V) ---
    $script:Gemerkt.Clear()
    $einzel = 'Kx7' + $z40
    $r1 = Protect-Text $einzel
    $r2 = Protect-Text "Fehler beim Login mit $einzel am Server"
    $ak = 'sk-ant-' + 'api03-' + $z40 + '_' + $z40 + '-AA'
    $einzelne = @(
        @('Zufallsstring allein', $einzel),
        @('Anthropic-Key allein', $ak),
        @('Entra-Secret allein',  ('abc8Q~' + 'dEfGhIjKlMnOpQrStUvWxYz0123456789a')),
        @('Nextcloud-PW allein',  'aB3dE-fG6hJ-kL9mN-pQ2rS-tU5vW'),
        @('GitHub-Token allein',  ('ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8')),
        @('Gemini-Key allein',    ('AIza' + 'SyD3mo-K3y_0123456789abcdefghijklmno')),
        @('JWT allein',           ('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' + '.' + 'eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20ifQ' + '.' + 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'))
    )
    foreach ($t in $einzelne) {
        $script:Gemerkt.Clear()
        $r = Protect-Text $t[1]
        if ($r.Nackt -and $r.Geaendert -and $r.Text -eq '[REDACTED]') { $ok++; Write-Host ("  +     {0,-22} -> [REDACTED]" -f $t[0]) -ForegroundColor Green }
        else { $fail++; Write-Host ("  FEHLT {0,-22} -> {1}" -f $t[0], $r.Text) -ForegroundColor Red }
    }
    if ($r2.Geaendert -and -not $r2.Text.Contains($einzel)) { $ok++; Write-Host "  +     Secret im Fliesstext geschwaerzt" -ForegroundColor Green }
    else { $fail++; Write-Host "  FEHLT Secret im Fliesstext: $($r2.Text)" -ForegroundColor Red }

    # --- Erkannt = gemerkt: spaeter auch allein und in Variationen ---
    $script:Gemerkt.Clear()
    $void = Protect-Text ('DB_PASSWORD=' + 'Sommer2026!xyz')
    $x2 = Protect-Text ('mein pw war ' + 'Sommer2026!xyz' + ' heute')
    if ($x2.Geaendert) { $ok++; Write-Host "  +     Aus Config erkanntes Passwort wird danach auch im Satz erkannt" -ForegroundColor Green }
    else { $fail++; Write-Host "  FEHLT Gemerktes Passwort im Satz: $($x2.Text)" -ForegroundColor Red }

    $script:Gemerkt.Clear()
    $geh  = 'Sommer-Gewitter#2026&x'
    $lang = 'Kx7' + $z40
    Add-Gemerkt $geh
    Add-Gemerkt $lang
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($geh))
    $var = @(
        @('im Satz',        "das war $geh oder so",                                                       $geh),
        @('GROSSBUCHSTABEN', "PW: $($geh.ToUpper()) ok",                                                   $geh.ToUpper()),
        @('URL-kodiert',    ('https://x.de/login?p=' + [uri]::EscapeDataString($geh) + '&u=max'),        [uri]::EscapeDataString($geh)),
        @('Base64',         ('ref=' + $b64),                                                              $b64),
        @('JSON-escaped',   ('{"p":"' + $geh.Replace('\', '\\').Replace('"', '\"') + '"}'),               $geh),
        @('Hex',            ('x=' + ([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($geh))).Replace('-', '').ToLower()), '736f6d6d6572'),
        @('umgebrochen',    ($geh.Substring(0, 11) + "`r`n" + $geh.Substring(11)),                        'tter#2026'),
        @('PowerShell-String', ('$p = "' + $geh.Replace('"', '`"').Replace('$', '`$') + '"'),             $geh),
        @('Bruchstueck vorne', ('Fehler bei ' + $lang.Substring(0, 16)),                                  $lang.Substring(0, 16)),
        @('Bruchstueck hinten', ('...' + $lang.Substring($lang.Length - 16) + ' abgelaufen'),             $lang.Substring($lang.Length - 16))
    )
    foreach ($t in $var) {
        $r = Protect-Text $t[1]
        if ($r.Geaendert -and -not $r.Text.ToLower().Contains($t[2].ToLower())) { $ok++; Write-Host ("  +     Variation: {0}" -f $t[0]) -ForegroundColor Green }
        else { $fail++; Write-Host ("  FEHLT Variation: {0} -> {1}" -f $t[0], $r.Text) -ForegroundColor Red }
    }
    $r4 = Protect-Text $r2.Text
    if (-not $r4.Geaendert) { $ok++; Write-Host "  +     Bereits geschwaerzter Text bleibt stabil" -ForegroundColor Green } else { $fail++; Write-Host "  FEHLT nicht idempotent: $($r4.Text)" -ForegroundColor Red }
    $script:Gemerkt.Clear()

    Write-Host ""
    if ($fail) { Write-Host ("  {0} von {1} fehlgeschlagen" -f $fail, ($ok + $fail)) -ForegroundColor Red }
    else { Write-Host ("  {0}/{0} " -f $ok) -ForegroundColor Green -NoNewline; Write-Host "bestanden" -ForegroundColor DarkGray }
    Write-Host ""
    if ($fail) { exit 1 }
    return
}

if ($Autostart) {
    $lnk = Join-Path ([Environment]::GetFolderPath('Startup')) "ClipGuard.lnk"
    if ($Autostart -eq "Aus") {
        if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force }
        Write-Host ""; Write-Host "  autostart aus" -ForegroundColor Yellow; Write-Host "  ClipGuard startet nicht mehr mit Windows.`n" -ForegroundColor DarkGray
    } else {
        $sh = New-Object -ComObject WScript.Shell
        $s = $sh.CreateShortcut($lnk)
        $s.TargetPath       = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
        $s.Arguments        = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $s.WorkingDirectory = $PSScriptRoot
        $s.WindowStyle      = 7
        $s.Description      = "ClipGuard - Secrets in der Zwischenablage schwaerzen"
        $s.Save()
        Write-Host ""; Write-Host "  autostart an" -ForegroundColor Magenta; Write-Host "  ClipGuard startet ab jetzt mit Windows.`n" -ForegroundColor DarkGray
    }
    return
}

# =====================================================================================================
#  TRAY-MODUS (Windows)
# =====================================================================================================
function Start-Tray {
$script:SkriptPfad = $PSCommandPath
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Namespace ClipGuard -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
[DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
'@
Add-Type -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' -TypeDefinition @'
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
namespace ClipGuard {
  public class Toast : Form {
    [DllImport("gdi32.dll")] static extern IntPtr CreateRoundRectRgn(int a, int b, int c, int d, int e, int f);
    public string Titel = "";
    public string Zeile = "";
    public Color Akzent = Color.FromArgb(226, 75, 74);
    protected override bool ShowWithoutActivation { get { return true; } }
    protected override CreateParams CreateParams {
      get { CreateParams cp = base.CreateParams; cp.ExStyle |= 0x08000000 | 0x80 | 0x8; return cp; }
    }
    public Toast() {
      FormBorderStyle = FormBorderStyle.None;
      StartPosition = FormStartPosition.Manual;
      ShowInTaskbar = false;
      TopMost = true;
      DoubleBuffered = true;
      Size = new Size(350, 78);
      BackColor = Color.FromArgb(32, 33, 36);
      Region = Region.FromHrgn(CreateRoundRectRgn(0, 0, Width + 1, Height + 1, 16, 16));
    }
    protected override void OnPaint(PaintEventArgs e) {
      Graphics g = e.Graphics;
      g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
      using (SolidBrush b = new SolidBrush(Akzent)) { g.FillRectangle(b, 0, 0, 6, Height); }
      using (Font f = new Font("Segoe UI Semibold", 10.5f))
      using (SolidBrush br = new SolidBrush(Color.White)) { g.DrawString(Titel, f, br, new RectangleF(22, 12, Width - 34, 24)); }
      using (Font f2 = new Font("Segoe UI", 9f))
      using (SolidBrush br2 = new SolidBrush(Color.FromArgb(185, 187, 190))) { g.DrawString(Zeile, f2, br2, new RectangleF(22, 38, Width - 34, 36)); }
    }
  }
  public class DunkelFarben : ProfessionalColorTable {
    static Color Bg = Color.FromArgb(32, 33, 36);
    static Color Hov = Color.FromArgb(60, 63, 68);
    static Color Rand = Color.FromArgb(70, 72, 77);
    public override Color ToolStripDropDownBackground { get { return Bg; } }
    public override Color ImageMarginGradientBegin { get { return Bg; } }
    public override Color ImageMarginGradientMiddle { get { return Bg; } }
    public override Color ImageMarginGradientEnd { get { return Bg; } }
    public override Color MenuBorder { get { return Rand; } }
    public override Color MenuItemBorder { get { return Hov; } }
    public override Color MenuItemSelected { get { return Hov; } }
    public override Color MenuItemSelectedGradientBegin { get { return Hov; } }
    public override Color MenuItemSelectedGradientEnd { get { return Hov; } }
    public override Color MenuItemPressedGradientBegin { get { return Hov; } }
    public override Color MenuItemPressedGradientMiddle { get { return Hov; } }
    public override Color MenuItemPressedGradientEnd { get { return Hov; } }
    public override Color SeparatorDark { get { return Rand; } }
    public override Color SeparatorLight { get { return Rand; } }
    public override Color CheckBackground { get { return Color.FromArgb(127, 119, 221); } }
    public override Color CheckSelectedBackground { get { return Color.FromArgb(127, 119, 221); } }
    public override Color CheckPressedBackground { get { return Color.FromArgb(127, 119, 221); } }
  }
}
'@

if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Host "Bitte über ClipGuard.cmd starten (braucht powershell -STA)." -ForegroundColor Red
    return
}

$neu = $false
$script:Mutex = New-Object System.Threading.Mutex($true, "Local\ClipGuard-Tray", [ref]$neu)
if (-not $neu) { return }   # läuft schon

if (-not (Test-Path -LiteralPath $script:DatenDir)) { [void](New-Item -ItemType Directory -Path $script:DatenDir -Force) }
$script:LogPfad  = Join-Path $script:DatenDir "protokoll.txt"
$script:CfgPfad  = Join-Path $script:DatenDir "config.json"
$script:PauseBis = [datetime]::MinValue
$script:HitBis   = [datetime]::MinValue
$script:Zaehler  = 0
$script:RxVerlaufBesitzer = '(?i)^(?:TextInputHost|ShellExperienceHost|StartMenuExperienceHost|ApplicationFrameHost|SearchHost|SearchApp|explorer|svchost|RuntimeBroker|sihost)$'
$script:LetzteSeq = [ClipGuard.Native]::GetClipboardSequenceNumber()

function script:Get-Besitzer {
    # Welcher Prozess hat die Zwischenablage zuletzt befuellt? (hilft, Win+V von einer frischen Kopie zu unterscheiden)
    try {
        $h = [ClipGuard.Native]::GetClipboardOwner()
        if ($h -eq [IntPtr]::Zero) { return "" }
        $procId = [uint32]0
        [void][ClipGuard.Native]::GetWindowThreadProcessId($h, [ref]$procId)
        if ($procId -eq 0) { return "" }
        return (Get-Process -Id $procId -ErrorAction Stop).ProcessName
    } catch { return "" }
}

function script:Test-Verlauf {
    # Ist der Windows-Zwischenablageverlauf (Win+V) nutzbar?  an / aus / gesperrt (Richtlinie)
    try {
        $p = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name AllowClipboardHistory -ErrorAction Stop).AllowClipboardHistory
        if ($p -eq 0) { return 'gesperrt' }
    } catch { }
    try {
        if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Clipboard' -Name EnableClipboardHistory -ErrorAction Stop).EnableClipboardHistory -eq 1) { return 'an' }
    } catch { }
    return 'aus'
}

function script:Add-Original([string]$Text, $Namen) {
    for ($i = $script:Originale.Count - 1; $i -ge 0; $i--) { if ($script:Originale[$i].Text -ceq $Text) { $script:Originale.RemoveAt($i) } }
    $script:Originale.Insert(0, [pscustomobject]@{ Text = $Text; Zeit = (Get-Date); Namen = (($Namen | Select-Object -First 2) -join ', ') })
    while ($script:Originale.Count -gt 10) { $script:Originale.RemoveAt($script:Originale.Count - 1) }
}

function script:Write-Protokoll([string]$Zeile) {
    # Es werden nur Regelnamen protokolliert, nie Inhalte.
    try {
        if ((Test-Path -LiteralPath $script:LogPfad) -and (Get-Item -LiteralPath $script:LogPfad).Length -gt 1MB) { Remove-Item -LiteralPath $script:LogPfad -Force }
        Add-Content -LiteralPath $script:LogPfad -Value ("{0:yyyy-MM-dd HH:mm:ss}  {1}" -f (Get-Date), $Zeile) -Encoding UTF8
    } catch { }
}

function script:Get-Zwischenablage {
    for ($i = 0; $i -lt 6; $i++) {
        try {
            $d = [System.Windows.Forms.Clipboard]::GetDataObject()
            if (-not $d) { return $null }
            $pm = $d.GetDataPresent("ExcludeClipboardContentFromMonitorProcessing") -or $d.GetDataPresent("Clipboard Viewer Ignore")
            $t = $null
            if ($d.GetDataPresent([System.Windows.Forms.DataFormats]::UnicodeText)) { $t = [string]$d.GetData([System.Windows.Forms.DataFormats]::UnicodeText) }
            return [pscustomobject]@{ Text = $t; Passwortmanager = $pm }
        } catch { Start-Sleep -Milliseconds 40 }
    }
    return $null
}

function script:Set-Zwischenablage([string]$Text) {
    for ($i = 0; $i -lt 6; $i++) {
        try {
            [System.Windows.Forms.Clipboard]::SetDataObject($Text, $true, 5, 40)
            $script:LetzteSeq = [ClipGuard.Native]::GetClipboardSequenceNumber()
            return $true
        } catch { Start-Sleep -Milliseconds 40 }
    }
    return $false
}

function script:Show-Hinweis([string]$Titel, [string]$Text, [string]$Art = "Info") {
    try {
        if ($script:ToastForm -and -not $script:ToastForm.IsDisposed) { $script:ToastTimer.Stop(); $script:ToastForm.Close() }
        $f = New-Object ClipGuard.Toast
        $f.Titel = $Titel
        $f.Zeile = $Text
        $f.Akzent = switch ($Art) {
            "Hit"     { [System.Drawing.Color]::FromArgb(127, 119, 221) }
            "Warning" { [System.Drawing.Color]::FromArgb(239, 159, 39) }
            "Error"   { [System.Drawing.Color]::FromArgb(226, 75, 74) }
            default   { [System.Drawing.Color]::FromArgb(127, 119, 221) }
        }
        $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $f.Location = New-Object System.Drawing.Point ($wa.Right - $f.Width - 16), ($wa.Bottom - $f.Height - 16)
        $f.add_Click({ $script:ToastForm.Close() })
        $script:ToastForm = $f
        $f.Show()
        $script:ToastTimer = New-Object System.Windows.Forms.Timer
        $script:ToastTimer.Interval = 3800
        $script:ToastTimer.add_Tick({ $script:ToastTimer.Stop(); try { $script:ToastForm.Close() } catch { } })
        $script:ToastTimer.Start()
    } catch {
        try { $script:Tray.ShowBalloonTip(4000, $Titel, $Text, [System.Windows.Forms.ToolTipIcon]::Info) } catch { }
    }
}

function script:Invoke-Pruefung {
    $seq = [ClipGuard.Native]::GetClipboardSequenceNumber()
    if ($seq -eq $script:LetzteSeq) { return }
    $script:LetzteSeq = $seq
    if ($script:Pausiert) { return }

    $c = Get-Zwischenablage
    if (-not $c -or -not $c.Text) { return }
    $text = $c.Text

    if ($c.Passwortmanager) {            # Passwortmanager-Kopie: nie anfassen (sonst gehen Logins kaputt), aber merken
        if ($text.Length -le 512 -and $text -notmatch "[\r\n]") { Add-Gemerkt $text }
        return
    }

    # Ein Original, das du bewusst aus Win+V zurueckholst, laesst ClipGuard durch (sonst wuerde es sofort wieder geschwaerzt)
    foreach ($o in $script:Originale) {
        if ($o.Text -ceq $text) {
            $b = Get-Besitzer
            if ($b -match $script:RxVerlaufBesitzer) {
                Write-Protokoll "Original aus dem Verlauf eingefügt (Besitzer: $b)"
                return
            }
            break
        }
    }

    $r = Protect-Text $text
    if ($r.Anzahl -eq 0) { return }
    $besitzer = Get-Besitzer

    Start-Sleep -Milliseconds 150        # Windows soll das Original noch in den Verlauf (Win+V) uebernehmen
    if ([ClipGuard.Native]::GetClipboardSequenceNumber() -ne $seq) { return }   # inzwischen etwas anderes kopiert

    if (Set-Zwischenablage $r.Text) {
        Add-Original $text $r.Namen
        $script:Zaehler += $r.Anzahl
        $script:Tray.Text = "ClipGuard · aktiv · $($script:Zaehler) geschwärzt"
        $script:Tray.Icon = $script:IconHit
        $script:HitBis = (Get-Date).AddSeconds(3)
        Update-Kopf
        Write-Protokoll ("{0} geschwärzt (Besitzer: {1}): {2}" -f $r.Anzahl, $besitzer, ($r.Namen -join ' | '))
        $namen = ($r.Namen | Select-Object -First 3) -join ', '
        $wo = if ((Test-Verlauf) -eq 'an') { 'Original: Win+V' } else { 'Original: Tray-Menü > Originale' }
        Show-Hinweis ("{0} Secret{1} geschwärzt" -f $r.Anzahl, $(if ($r.Anzahl -gt 1) { 's' } else { '' })) "$namen`n$wo" "Hit"
    }
}

# ---- Tray-Symbol + Menue ----
    function script:Test-Autostart { return (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) "ClipGuard.lnk")) }

    function script:New-Symbol([string]$Art) {
        # Schlankes Outline-Schild (64 px, wird vom System scharf herunterskaliert) + Statuspunkt: gruen = aktiv, gelb = pausiert, rot + violett gefuellt = gerade geschwaerzt
        try {
            $bmp = New-Object System.Drawing.Bitmap 64, 64
            $gfx = [System.Drawing.Graphics]::FromImage($bmp)
            $gfx.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $gfx.Clear([System.Drawing.Color]::Transparent)
            $pts = [System.Drawing.Point[]]@((New-Object System.Drawing.Point 32, 6), (New-Object System.Drawing.Point 55, 14), (New-Object System.Drawing.Point 55, 31), (New-Object System.Drawing.Point 50, 45), (New-Object System.Drawing.Point 32, 59), (New-Object System.Drawing.Point 14, 45), (New-Object System.Drawing.Point 9, 31), (New-Object System.Drawing.Point 9, 14))
            switch ($Art) {
                'pause' { $kontur = [System.Drawing.Color]::FromArgb(150, 150, 150); $punkt = [System.Drawing.Color]::FromArgb(227, 179, 65); $fuell = $null }
                'hit'   { $kontur = [System.Drawing.Color]::FromArgb(175, 169, 236); $punkt = [System.Drawing.Color]::FromArgb(248, 81, 73); $fuell = [System.Drawing.Color]::FromArgb(127, 119, 221) }
                default { $kontur = [System.Drawing.Color]::White; $punkt = [System.Drawing.Color]::FromArgb(63, 185, 80); $fuell = $null }
            }
            if ($fuell) { $pf = New-Object System.Drawing.SolidBrush $fuell; $gfx.FillPolygon($pf, $pts); $pf.Dispose() }
            $dunkel = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(40, 40, 44)), 10
            $dunkel.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
            $gfx.DrawPolygon($dunkel, $pts)
            $stift = New-Object System.Drawing.Pen $kontur, 5.5
            $stift.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
            $gfx.DrawPolygon($stift, $pts)
            $ring = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(40, 40, 44))
            $gfx.FillEllipse($ring, 34, 34, 28, 28)
            $pp = New-Object System.Drawing.SolidBrush $punkt
            $gfx.FillEllipse($pp, 38, 38, 20, 20)
            $dunkel.Dispose(); $stift.Dispose(); $ring.Dispose(); $pp.Dispose(); $gfx.Dispose()
            return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
        } catch {
            if ($Art -eq 'pause') { return [System.Drawing.SystemIcons]::Warning } else { return [System.Drawing.SystemIcons]::Shield }
        }
    }

    function script:Update-Kopf {
        if ($script:MiKopf) {
            if ($script:Pausiert) {
                $script:MiKopf.Text = "●  Pausiert (5 Min)"
                $script:MiKopf.ForeColor = [System.Drawing.Color]::FromArgb(239, 159, 39)
            } else {
                $script:MiKopf.Text = "●  Schutz aktiv  ·  $($script:Zaehler) geschwärzt"
                $script:MiKopf.ForeColor = [System.Drawing.Color]::FromArgb(63, 185, 80)
            }
        }
        Update-StatusListe
    }

    function script:Update-StatusListe {
        if (-not $script:StatusForm -or $script:StatusForm.IsDisposed) { return }
        $as = if (Test-Autostart) { "Autostart an" } else { "Autostart aus" }
        if ($script:Pausiert) { $script:LblStatus.Text = "pausiert  ·  $as"; $script:LblStatus.ForeColor = [System.Drawing.Color]::FromArgb(227, 179, 65) }
        else { $script:LblStatus.Text = "aktiv  ·  $as"; $script:LblStatus.ForeColor = [System.Drawing.Color]::FromArgb(127, 119, 221) }
        $script:LblInfo.Text = "{0} Regeln  ·  {1} geschwärzt seit Start" -f ($script:Regeln.Count + $script:GlRegeln.Count), $script:Zaehler
        $script:StatusListe.Items.Clear()
        $zeilen = @()
        if (Test-Path -LiteralPath $script:LogPfad) { try { $zeilen = @(Get-Content -LiteralPath $script:LogPfad -Tail 300 -Encoding UTF8) } catch { } }
        $n = 0
        for ($i = $zeilen.Count - 1; $i -ge 0 -and $n -lt 40; $i--) {
            if ($zeilen[$i] -match '^\d{4}-\d\d-\d\d (\d\d:\d\d):\d\d\s+(\d+) geschw\S+ \(Besitzer: [^)]*\): (.+)$') {
                $txt = $Matches[3]
                if ([int]$Matches[2] -gt 1) { $txt = "$($Matches[2]) ×  $txt" }
                $it = New-Object System.Windows.Forms.ListViewItem $Matches[1]
                [void]$it.SubItems.Add($txt)
                [void]$script:StatusListe.Items.Add($it)
                $n++
            }
        }
        if ($n -eq 0) {
            $it = New-Object System.Windows.Forms.ListViewItem ""
            [void]$it.SubItems.Add("Noch nichts geschwärzt.")
            $it.ForeColor = [System.Drawing.Color]::FromArgb(154, 160, 166)
            [void]$script:StatusListe.Items.Add($it)
        }
    }

    function script:Show-Status {
        if ($script:StatusForm -and -not $script:StatusForm.IsDisposed) { $script:StatusForm.Activate(); Update-StatusListe; return }
        $cBg = [System.Drawing.Color]::FromArgb(32, 33, 36)
        $cPanel = [System.Drawing.Color]::FromArgb(44, 45, 49)
        $cText = [System.Drawing.Color]::FromArgb(232, 234, 237)
        $cMute = [System.Drawing.Color]::FromArgb(154, 160, 166)
        $f = New-Object System.Windows.Forms.Form
        $f.Text = "ClipGuard"
        $f.ClientSize = New-Object System.Drawing.Size 470, 440
        $f.StartPosition = "CenterScreen"
        $f.FormBorderStyle = "FixedSingle"
        $f.MaximizeBox = $false
        $f.BackColor = $cBg
        $f.ForeColor = $cText
        $f.Font = New-Object System.Drawing.Font "Segoe UI", 9.5
        $f.Icon = $script:IconAn
        $script:LblStatus = New-Object System.Windows.Forms.Label
        $script:LblStatus.AutoSize = $true
        $script:LblStatus.Font = New-Object System.Drawing.Font "Segoe UI Semibold", 14
        $script:LblStatus.Location = New-Object System.Drawing.Point 20, 16
        $script:LblInfo = New-Object System.Windows.Forms.Label
        $script:LblInfo.AutoSize = $true
        $script:LblInfo.ForeColor = $cMute
        $script:LblInfo.Location = New-Object System.Drawing.Point 22, 48
        $lv = New-Object System.Windows.Forms.ListView
        $lv.View = "Details"
        $lv.FullRowSelect = $true
        $lv.HeaderStyle = "None"
        $lv.BorderStyle = "None"
        $lv.BackColor = $cPanel
        $lv.ForeColor = $cText
        $lv.Location = New-Object System.Drawing.Point 20, 82
        $lv.Size = New-Object System.Drawing.Size 430, 290
        [void]$lv.Columns.Add("Zeit", 70)
        [void]$lv.Columns.Add("Secret", 340)
        $script:StatusListe = $lv
        $tt = New-Object System.Windows.Forms.ToolTip
        $btnDef = @(
            @("Merken", "Aktuelle Zwischenablage als Secret merken", { 
                $c = Get-Zwischenablage
                if ($c -and $c.Text -and $c.Text.Trim().Length -ge 8) { Add-Gemerkt $c.Text; Show-Hinweis "Gemerkt" "Wird ab jetzt in jedem größeren Text geschwärzt." "Info" }
                else { Show-Hinweis "Nicht gemerkt" "Zwischenablage leer oder kürzer als 8 Zeichen." "Warning" } }),
            @("Vergessen", "Gemerkte Secrets und Originale aus dem RAM entfernen", {
                $script:Gemerkt.Clear(); $script:Originale.Clear()
                Show-Hinweis "Vergessen" "Gemerkte Secrets und Originale sind weg." "Info" }),
            @("Regeln laden", "Eigene Regeln neu einlesen", {
                Initialize-Regeln; Update-StatusListe
                Show-Hinweis "Regeln neu eingelesen" "$($script:Regeln.Count) eigene + $($script:GlRegeln.Count) gitleaks-Regeln aktiv." "Info" }),
            @("gitleaks", "gitleaks-Regeln laden / aktualisieren", {
                try { $n = Update-Gitleaks; Update-StatusListe; Show-Hinweis "Regeln aktualisiert" "$n gitleaks-Regeln geladen." "Info" }
                catch { Show-Hinweis "Update fehlgeschlagen" $_.Exception.Message "Error" } }),
            @("Autostart", "Autostart an- oder ausschalten", {
                $arg = if (Test-Autostart) { "Aus" } else { "An" }
                try { Start-Process -FilePath (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe") -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($script:SkriptPfad)`" -Autostart $arg" -WindowStyle Hidden -Wait } catch { }
                Update-StatusListe
                Show-Hinweis "Autostart" $(if (Test-Autostart) { "ClipGuard startet jetzt mit Windows." } else { "ClipGuard startet nicht mehr mit Windows." }) "Info" })
        )
        $x = 20
        foreach ($d in $btnDef) {
            $b = New-Object System.Windows.Forms.Button
            $b.Text = $d[0]
            $b.Size = New-Object System.Drawing.Size 80, 32
            $b.Location = New-Object System.Drawing.Point $x, 388
            $b.FlatStyle = "Flat"
            $b.FlatAppearance.BorderSize = 0
            $b.BackColor = $cPanel
            $b.ForeColor = $cText
            $b.add_Click($d[2])
            $tt.SetToolTip($b, $d[1])
            $f.Controls.Add($b)
            $x += 87
        }
        $f.Controls.AddRange(@($script:LblStatus, $script:LblInfo, $lv))
        $f.add_Activated({ Update-StatusListe })
        $script:StatusForm = $f
        Update-StatusListe
        $f.Show()
    }

    function script:Set-Status([bool]$Pause) {
        if ($Pause) {
            $script:PauseBis = (Get-Date).AddMinutes(5)
            $script:HitBis = [datetime]::MinValue
            $script:Tray.Icon = $script:IconAus
            $script:Tray.Text = "ClipGuard · Pause (5 Min, Klick = an)"
        } else {
            $script:PauseBis = [datetime]::MinValue
            $script:Tray.Icon = $script:IconAn
            $script:Tray.Text = "ClipGuard · aktiv · $($script:Zaehler) geschwärzt"
            $script:LetzteSeq = [ClipGuard.Native]::GetClipboardSequenceNumber()   # was in der Pause kopiert wurde, bleibt
        }
        $script:Pausiert = $Pause
        if ($script:MiPause) { $script:MiPause.Checked = $Pause }
        Update-Kopf
    }

    $script:Pausiert = $false
    $script:IconAn  = New-Symbol 'an'
    $script:IconAus = New-Symbol 'pause'
    $script:IconHit = New-Symbol 'hit'
    $script:Tray = New-Object System.Windows.Forms.NotifyIcon
    $script:Tray.Icon = $script:IconAn
    $script:Tray.Text = "ClipGuard · aktiv · 0 geschwärzt"
    $script:Tray.add_MouseClick({
        param($quelle, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Set-Status (-not $script:Pausiert) }
    })
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $menu.Renderer = New-Object System.Windows.Forms.ToolStripProfessionalRenderer (New-Object ClipGuard.DunkelFarben)
    $menu.BackColor = [System.Drawing.Color]::FromArgb(32, 33, 36)
    $menu.ForeColor = [System.Drawing.Color]::FromArgb(232, 234, 237)
    $menu.Font = New-Object System.Drawing.Font "Segoe UI", 10
    $menu.ShowImageMargin = $false
    $menu.ShowCheckMargin = $true

    $script:MiPause = $menu.Items.Add("Pause 5 Min")
    $script:MiPause.add_Click({ Set-Status (-not $script:Pausiert) })

    $script:MiOrig = $menu.Items.Add("Originale anzeigen")
    $ph = $script:MiOrig.DropDownItems.Add("(noch nichts geschwärzt)")
    $ph.Enabled = $false
    $script:MiOrig.add_DropDownOpening({
        $script:MiOrig.DropDownItems.Clear()
        if ($script:Originale.Count -eq 0) {
            $leer = $script:MiOrig.DropDownItems.Add("(noch nichts geschwärzt)")
            $leer.Enabled = $false
            return
        }
        foreach ($o in $script:Originale) {
            $kopf = if ($o.Text.Length -gt 4) { $o.Text.Substring(0, 3) + "…" } else { "…" }
            $it = $script:MiOrig.DropDownItems.Add(("{0:HH:mm:ss}  {1}  {2}  ({3} Zeichen)" -f $o.Zeit, $o.Namen, $kopf, $o.Text.Length))
            $it.Tag = $o.Text
            $it.add_Click({
                param($quelle, $e)
                if (Set-Zwischenablage ([string]$quelle.Tag)) {
                    Write-Protokoll "Original aus dem Tray-Menü zurückgeholt"
                    Show-Hinweis "Original in der Zwischenablage" "Jetzt Strg+V. Beim nächsten Kopieren ist es wieder geschützt." "Info"
                }
            })
        }
    })

    $miLog = $menu.Items.Add("Status-Fenster")
    $miLog.add_Click({ Show-Status })

    [void]$menu.Items.Add("-")

    $miEnde = $menu.Items.Add("Beenden")
    $miEnde.add_Click({ $script:Ctx.ExitThread() })

    Update-Kopf
    $script:Tray.ContextMenuStrip = $menu
$script:Tray.Visible = $true

$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 100
$script:Timer.add_Tick({
    try {
        Invoke-Pruefung
        if ($script:Pausiert -and (Get-Date) -ge $script:PauseBis) { Set-Status $false }
        if ($script:HitBis -ne [datetime]::MinValue -and (Get-Date) -ge $script:HitBis) {
            $script:HitBis = [datetime]::MinValue
            if (-not $script:Pausiert) { $script:Tray.Icon = $script:IconAn }
        }
    } catch { Write-Protokoll ("Fehler: " + $_.Exception.Message) }
})
$script:Timer.Start()

$vs = Test-Verlauf
Write-Protokoll "gestartet ($($script:Regeln.Count) eigene + $($script:GlRegeln.Count) gitleaks-Regeln, Win+V-Verlauf: $vs)"
if ($vs -eq 'an') {
    Show-Hinweis "ClipGuard aktiv" "$($script:Regeln.Count + $script:GlRegeln.Count) Regeln geladen." "Info"
} else {
    Show-Hinweis "ClipGuard aktiv" "Win+V-Verlauf ist $vs. Originale nur über Tray-Menü > Originale." "Warning"
}

$script:Ctx = New-Object System.Windows.Forms.ApplicationContext
try { [System.Windows.Forms.Application]::Run($script:Ctx) }
finally {
    $script:Timer.Stop()
    $script:Tray.Visible = $false
    $script:Tray.Dispose()
    $script:Gemerkt.Clear()
    $script:Originale.Clear()
    try { $script:Mutex.ReleaseMutex() } catch { }
}
}

Start-Tray
