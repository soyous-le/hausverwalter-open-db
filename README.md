# DB-Zugriff auf Hausverwalter Software direkt unter Windows (read‑only)

> **Hinweis:** Dieses Projekt steht in keinerlei Verbindung zur Buhl Data Service GmbH
> oder zur Marke „WISO" und wird von diesen weder unterstützt noch genehmigt. „WISO
> Hausverwalter" und alle genannten Produkt‑ und Firmennamen sind Eigentum ihrer jeweiligen
> Inhaber und werden hier nur zu Beschreibungszwecken verwendet. Es handelt sich um eine 
> Anleitung für den Zugriff auf die **eigenen Daten** auf dem **eigenen System**.

Anleitung, um die Buchhaltungsdaten aus einem lokal installierten **WISO Hausverwalter 365** direkt zu lesen, wenn man
**am Windows‑System selbst** mit Admin Rechten angemeldet ist. Das Programm selbst muss auch erfolgreich gestartet werden und auf die Daten zugreifen können (diese Anleitung ist also nicht für defekte Installationen oder reine Backups geeignet).


---

## 1. So funktioniert es (Kurz)

Die Daten liegen in `hv.db`, bereitgestellt von einem eingebetteten **cubeSQL‑Server**
(SQLabs v5.9). Die Datei ist mit **SQLite SEE (AES‑128‑OFB)** verschlüsselt – eine Dateikopie
ist wertlos. Der **laufende Server entschlüsselt transparent**, sobald man sich anmeldet.

- Server lauscht lokal auf `[::1]:4422` (IPv6‑Loopback) und verlangt TLS.
- Login‑Benutzer: `hv_admin`. **Kein Klartext‑Passwort nötig**: der cubeSQL‑Handshake
  (innerhalb TLS) braucht nur `SHA1(SHA1(passwort))` – und genau dieser Hash steht im
  Bootstrap‑SQL des Servers (`hserver365.dll`):
  ```sql
  INSERT INTO Users (userid, username, password)
  VALUES (1, 'hv_admin', '<HASH>')
  ```
  Base64‑dekodiert = der benötigte Hash. Es ist keinerlei "Passwort-Knacken oder Nachbau von proprietären Bestandteilen nötig.

Bedingung: Der cubeSQL‑Server muss laufen. Er startet mit WISO Hausverwalter; solange der
Prozess lebt, lauscht `[::1]:4422`. Prüfen:
```cmd
netstat -ano -p tcpv6 | findstr 4422
```

---

## 2. Voraussetzungen (einmalig)

1. **Python 3** für Windows installieren (python.org). Beim Setup „Add python.exe to PATH".
2. Abhängigkeit installieren:
   ```cmd
   pip install pycryptodome
   ```
3. Die drei Skripte in einen Ordner legen, z. B. `C:\hv-tools\`:
   `cubeclient.py`, `cubecrypto.py`, `backup.py`

---

## 3. Anmelde‑Hash aus der Programmdatei holen

Zum Anmelden genügt der gespeicherte Hash `base64(SHA1(SHA1(passwort)))` - das Klartext‑
Passwort wird nicht gebraucht. Dieser Hash steht als Klartext‑String im cubeSQL‑Server‑
Binary `hserver365.dll`. Die DLL enthält die eingebettete cubeSQL‑Engine; beim allerersten
Anlegen der Server‑Datenbank führt sie ein fest einkompiliertes Bootstrap‑SQL aus, das den
Default‑Benutzer `hv_admin` anlegt. Genau diese Zeile suchen wir.

Datei:
`C:\Program Files\Buhl\WISO Hausverwalter 365\hserver365.dll`

### Weg A: PowerShell (ohne Zusatz‑Tools)
```powershell
$dll = "C:\Program Files\Buhl\WISO Hausverwalter 365\hserver365.dll"
$txt = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($dll))
[regex]::Matches($txt, "INSERT INTO Users[^\x00]{0,110}") | ForEach-Object { $_.Value }
```
Ausgabe sind drei Treffer. Zwei sind Vorlagen mit Platzhaltern
(`... VALUES ('%s')` bzw. `('%s', '%s')`) – die ignorieren. Der gesuchte Treffer ist der mit
**konkreten Werten**:
```sql
INSERT INTO Users (userid, username, password) VALUES (1, 'hv_admin', '<HASH>')
```
Noch gezielter nur diese Zeile:
```powershell
[regex]::Match($txt, "INSERT INTO Users \(userid[^\x00]{0,90}").Value
```

### Weg B: Sysinternals `strings` (oder Git‑Bash/WSL)
```cmd
strings64.exe -n 10 "C:\Program Files\Buhl\WISO Hausverwalter 365\hserver365.dll" | findstr hv_admin
```
bzw. unter Linux/WSL auf eine Kopie der DLL:
```bash
strings -n 10 hserver365.dll | grep "INSERT INTO Users"
```

### Den String deuten
Das dritte Feld ist **nicht** das Klartext‑Passwort, sondern cubeSQLs Speicherform
`base64(SHA1(SHA1(passwort)))`. Prüfen: Base64 dekodiert zu genau **20 Byte** = SHA‑1‑Länge →
also `SHA1(SHA1(pw))`. Das ist exakt der Wert, den der clear‑in‑TLS‑Handshake als inneren Term
braucht (siehe Abschnitt 1) – deshalb genügt dieser Hash zum Anmelden, ohne das Klartext‑
Passwort zu kennen.

```powershell
# Gegenprobe: Base64 -> Byte-Länge (soll 20 sein)
[Convert]::FromBase64String("<HASH>").Length
```

### Hash setzen
Den gefundenen Hash (das dritte Feld, inkl. abschließendem `=`) als Umgebungsvariable
`CUBE_HH` hinterlegen – daraus lesen die Skripte den Login (Abschnitt 4):
```cmd
set CUBE_HH=<hier den gefundenen Hash einsetzen>
```
```powershell
$env:CUBE_HH="<hier den gefundenen Hash einsetzen>"
```

---

## 4. Verbinden & Daten holen

In einer Eingabeaufforderung (cmd) im Skriptordner. Dem Client sagen, dass er direkt zum
lokalen IPv6‑Server soll, und den in Abschnitt 3 ermittelten Hash mitgeben:

```cmd
cd C:\hv-tools
set CUBE_HOST=::1
set CUBE_PORT=4422
set CUBE_HH=<hier den gefundenen Hash einsetzen>
```
(PowerShell statt cmd: `$env:CUBE_HOST="::1"; $env:CUBE_PORT="4422"; $env:CUBE_HH="<Hash>"`)

Dann:

```cmd
:: Datenbanken auflisten (Verbindungstest)
python cubeclient.py probe

:: komplettes Schema (Tabellen + Views)
python cubeclient.py schema

:: EINE Abfrage als CSV (nach stdout; in Datei umleiten mit > )
python cubeclient.py sql "SELECT * FROM eurVerbucht LIMIT 20"

:: ALLE Tabellen nach CSV exportieren
python cubeclient.py dump C:\hv-tools\export_hv

:: vollständige SQLite-Sicherung (Schema + Indizes + FKs + Daten)
python backup.py C:\hv-tools\hv_backup.db
```

Login‑Parameter (per Env, siehe oben):
- `CUBE_USER` – Default `hv_admin`
- `CUBE_HH`   – der in Abschnitt 3 ermittelte Hash (`base64(SHA1(SHA1(pw)))`); **muss gesetzt sein**


---

## 5. Zwei Export‑Wege: CSV und vollständige SQLite‑Rekonstruktion

### 5a. CSV‑Export aller Tabellen (`dump`)
Exportiert jede Tabelle als eigene `.csv` (eine Kopfzeile + Daten, UTF‑8):
```cmd
python cubeclient.py dump C:\hv-tools\export_hv
```
Ergebnis: ein Ordner mit **einer CSV pro Tabelle** (über 100 Dateien). Gut für
Excel/LibreOffice, schnelles Durchsehen, Weiterverarbeitung. Fortschritt läuft nach stderr
(`Tabellenname: N rows`). Einzelne Abfragen als CSV gehen auch direkt:
```cmd
python cubeclient.py sql "SELECT * FROM table_name" > buchungszeilen.csv
```
> Hinweis: CSV verliert Typen, Indizes, Constraints und Beziehungen – dafür ist 5b da.

### 5b. Vollständige SQLite‑Rekonstruktion (`backup.py`)
```cmd
python backup.py C:\hv-tools\hv_backup.db
```
`backup.py` liest das Original‑Schema aus `sqlite_master` und baut aus den
`CREATE`-Statements eine **echte lokale SQLite‑Datei** in der Reihenfolge
Tabellen → Daten → Indizes → Views → Trigger, typрichtig inkl. BLOB, und prüft am Ende
`PRAGMA integrity_check` + `foreign_key_check`.

Die Datei lässt sich in DB Browser for SQLite, `sqlite3` o. Ä. öffnen

Schnelltest der erzeugten Datei:
```cmd
sqlite3 C:\hv-tools\hv_backup.db "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

---

## 6. Die Scripte:

- **`cubecrypto.py`** – exakte Portierung von cubeSQLs `encrypt_buffer`/`decrypt_buffer`
  (AES‑CBC mit Ciphertext‑Stealing) aus dem offiziellen SDK (`github.com/cubesql/sdk`).
  Selbsttest: `python cubecrypto.py` → `ROUNDTRIP OK`.
- **`cubeclient.py`** – read‑only cubeSQL‑Client: TLS‑Wrapper, clear‑/AES‑Handshake,
  `SELECT`, Cursor‑Parsing inkl. Chunking/Kompression. Kommandos `probe`/`schema`/`sql`/`dump`.
- **`backup.py`** – rekonstruiert die lokale SQLite‑Datei (s. Abschnitt 5).

---

## 7. Schreibzugriff

Derselbe Kanal kann schreiben (`UPDATE`/`INSERT`/`DELETE`), der Server übernimmt die
Verschlüsselung. **Risiko:** umgeht die Programmlogik (Trigger, Opos‑Verknüpfungen,
Konsistenzregeln). Empfehlung falls gewünscht: erst Backup, Änderungen zuerst
gegen die rekonstruierte Kopie testen, dann eng begrenzte Statements in einer Transaktion.