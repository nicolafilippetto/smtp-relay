# Triage report SAST — SMTP Relay

**Scansione:** HCL AppScan — SAST 2026-06-04 (`smtp-relay-fork`, branch `main`)
**Commit analizzato:** `3b67bda0abf50458ed4a9657078c0c75f87af69f`
**Documento redatto:** 2026-06-04
**Totale finding:** 10 (3 High, 7 Medium) su 7 tipologie

Questo documento risponde, finding per finding, alla scansione SAST, distinguendo
i **falsi positivi** (con la motivazione tecnica) dalle voci effettivamente
corrette o accettate.

---

## Quadro di sintesi

| # | Severità | Tipologia | File:riga | CWE | Esito |
|---|----------|-----------|-----------|-----|-------|
| 1 | High   | Hardcoded credentials | `common/models.py:77` | 522 | ❌ Falso positivo |
| 2 | Medium | Insecure base image version | `relay/Dockerfile:7`, `nginx/Dockerfile:14`, `ui/Dockerfile:7` | 16 | ✅ Risolto |
| 3 | Medium | XSS — autoescape false | `ui/templating.py:29` | 79 | ❌ Falso positivo |
| 4 | Medium | Exposure of confidential info (print) | `windows/launcher.py:134-135` | 497 | ❌ Falso positivo (comportamento voluto) |
| 5 | High   | OS command injection (VB) | `windows/start-tray.vbs:6` | 78 | ❌ Falso positivo |
| 6 | Medium | Path traversal | `windows/icons/generate_icons.py:44` | 73 | ❌ Falso positivo |
| 7 | High   | No non-root USER in Dockerfile | `nginx/Dockerfile:1` | 266 | ✅ Risolto |

**Esito complessivo:** 6 istanze su 10 (5 tipologie su 7) sono **falsi positivi**.
Le finding effettivamente valide sono state **corrette**: nginx non-root (#7) e
il pinning delle immagini base (#2, 3 istanze). Non resta alcuna vulnerabilità
sfruttabile aperta.

> Nota: le tre finding che AppScan stesso marca come **"Passed"** nel report
> (#1, #3, #6) coincidono con i falsi positivi più evidenti — il motore le ha
> già auto-declassate a rumore.

---

## Dettaglio falsi positivi

### #1 — Hardcoded credentials (High, CWE-522) — `common/models.py:77`

**Codice segnalato:** `USERNAME = "username"`

**Perché è stato segnalato:** il tool fa match sul nome `USERNAME` associato a
una stringa letterale e lo interpreta come credenziale incorporata nel sorgente.

**Perché NON è una vulnerabilità:** la riga è un membro di una `enum`, non una
credenziale. Indica *il tipo di bersaglio* di un ban (un IP oppure uno username):

```python
class BanScope(str, enum.Enum):
    """Whether a ban row targets an IP or a username."""
    IP = "ip"
    USERNAME = "username"
```

La stringa `"username"` è un'etichetta di categoria salvata a DB, non un segreto.
Le vere credenziali (password admin, account SMTP, client secret Entra ID) non
stanno nel codice: sono hashate (Argon2/bcrypt) o cifrate (Fernet) e inserite a
runtime dalla UI.

---

### #3 — Cross-Site Scripting / autoescape false (Medium, CWE-79) — `ui/templating.py:29`

**Codice segnalato:** inizializzazione di `jinja2.Environment(...)`

**Perché è stato segnalato:** il tool cerca `Environment(...)` privo di
auto-escaping abilitato e non riesce a risolvere il valore restituito dalla
funzione `select_autoescape`.

**Perché NON è una vulnerabilità:** l'auto-escaping **è attivo**. È esattamente
la correzione che il report stesso raccomanda:

```python
_env = Environment(
    loader=FileSystemLoader(str(_templates_dir)),
    autoescape=select_autoescape(("html", "xml")),  # <-- escaping attivo su .html/.xml
    trim_blocks=True,
    lstrip_blocks=True,
)
```

`select_autoescape(("html", "xml"))` abilita l'escaping per i template HTML/XML.
Output XSS-sensibile = nessuno non protetto.

---

### #4 — Exposure of confidential info via print (Medium, CWE-497) — `windows/launcher.py:134-135`

**Codice segnalato:**
```python
print(f"ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}")
print(f"SECRET_KEY={secrets.token_urlsafe(64)}")
```

**Perché è stato segnalato:** il tool rileva la stampa di valori "sensibili"
(chiavi) e teme la fuga di informazioni in log/messaggi d'errore.

**Perché NON è una vulnerabilità:** è il comando CLI `genkey`, il cui **unico
scopo** è generare chiavi nuove e stamparle su stdout, così che lo script di
installazione (`install.ps1`) le catturi e le scriva in `config.env`. Punti
chiave:

- Non sono segreti *preesistenti* che trapelano: sono valori casuali **appena
  generati** in quel momento, destinati proprio a essere mostrati all'operatore.
- Non c'è alcun canale verso un attaccante: nessuna richiesta web, nessuno stack
  trace, nessun log applicativo. È un'utility locale eseguita dall'amministratore
  durante l'installazione.
- È lo stesso pattern di strumenti standard come `openssl rand`, `wg genkey`,
  `ssh-keygen`.

La CWE-497 riguarda la divulgazione di dettagli interni (es. stack trace) verso
l'utente di un'applicazione web: non si applica a questo contesto.

---

### #5 — OS command injection in VB code (High, CWE-78) — `windows/start-tray.vbs:6`

**Codice segnalato:** `Set shell = CreateObject("WScript.Shell")`

**Perché è stato segnalato:** il tool segnala qualsiasi uso di `WScript.Shell` +
`.Run` come potenziale command injection.

**Perché NON è una vulnerabilità:** **non esiste alcun input utente/esterno** che
finisca nel comando eseguito. L'intero script:

```vbs
Set shell = CreateObject("WScript.Shell")
scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
exePath = scriptDir & "app\smtp-relay.exe"
shell.Run """" & exePath & """ tray", 0, False
```

- Il comando lanciato è un eseguibile a percorso **fisso** (`app\smtp-relay.exe`),
  derivato dal percorso dello *stesso script* (`WScript.ScriptFullName`).
- Il percorso è inoltre racchiuso tra virgolette.
- Non ci sono parametri, argomenti o variabili controllabili da un attaccante a
  runtime.

L'unico modo per "iniettare" sarebbe scrivere file nella cartella d'installazione,
il che presuppone già accesso in scrittura al filesystem (compromissione
preesistente — tema di permessi NTFS, non di command injection).

---

### #6 — Path traversal (Medium, CWE-73) — `windows/icons/generate_icons.py:44`

**Codice segnalato:** `os.path.join(HERE, name)`

**Perché è stato segnalato:** il tool segnala `os.path.join` con una variabile
come possibile path traversal.

**Perché NON è una vulnerabilità:** è uno **script di build/sviluppo** che genera
le icone dell'applicazione. Non riceve input esterni:

- `HERE` è la cartella dello script stesso (`os.path.dirname(os.path.abspath(__file__))`).
- `name` proviene esclusivamente da stringhe **hardcoded** nel codice
  (`"app.ico"`, `"start.ico"`, `"stop.ico"`, ...), passate da `main()`.

Nessuna richiesta HTTP, nessun parametro utente, nessun dato non fidato. Lo script
non viene nemmeno eseguito in produzione: serve solo a rigenerare gli asset.

---

## Voci effettivamente corrette

### #7 — No non-root USER in Dockerfile (High, CWE-266) — `nginx/Dockerfile:1` — ✅ Risolto

**Esito:** finding **legittima**, corretta.

Il container nginx era l'unico a girare come root (UI e relay già usavano un utente
non privilegiato). È stato corretto:

- immagine base passata a `nginxinc/nginx-unprivileged` (processo come uid 101);
- direttiva `USER` esplicita nel Dockerfile;
- nginx in ascolto su porte alte (8080/8443), mappate sulle 80/443 dell'host;
- aggiunti al servizio nginx, in linea con UI/relay: `read_only`, `cap_drop: ALL`,
  `no-new-privileges`, filesystem temporaneo `tmpfs`.

---

### #2 — Insecure base image version (Medium, CWE-16) — 3 Dockerfile — ✅ Risolto

**Finding:** le immagini base erano pinnate a `major.minor`
(`python:3.12-slim-bookworm`, `nginx:1.29-alpine`) ma non a un digest SHA256 —
una *best practice* (build riproducibili, protezione da tag mutabili), non una
vulnerabilità sfruttabile.

**Esito:** tutti e tre i `FROM` sono ora pinnati a un **digest SHA256 immutabile**
(il tag leggibile è mantenuto a fianco):

- `relay/Dockerfile`, `ui/Dockerfile`: `python:3.12-slim-bookworm@sha256:93ab4b…`
- `nginx/Dockerfile`: `nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d5…`

Per evitare lo svantaggio del pinning (immagini "congelate" che non ricevono più
patch), è stato aggiunto **`.github/dependabot.yml`** (ecosistema `docker`,
cadenza settimanale): i bump dei digest arrivano come PR revisionabili, che il
workflow `docker-publish` ricompila e ripubblica. Build riproducibili + patch
mantenute.

---

## Riepilogo per il revisore

- **5 tipologie su 7 (6 finding su 10) sono falsi positivi** dovuti a pattern
  matching del tool che non considera il contesto (enum scambiata per credenziale,
  `select_autoescape` non risolto, comando CLI di generazione chiavi, script
  privi di input esterni).
- **Le finding valide sono state corrette:** nginx non-root + hardening del
  servizio (#7) e pinning delle immagini base a digest SHA256 con bump
  automatici via Dependabot (#2).

Non resta alcuna vulnerabilità sfruttabile aperta.
