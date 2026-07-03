# Verbleibende Sicherheitsrisiken — finLai

## Akzeptiert (mit Begründung)

### 1. Salt-Datei Verlust

**Risiko:** Wenn `~/.finlai/.salt` gelöscht wird, sind alle
verschlüsselten Daten (Chat-Verläufe, API-Keys, Übersetzungshistorie)
unwiederbringlich verloren.

**Mitigiert durch:** Hinweis in der UI beim ersten Start.

**Empfehlung:** Backup-Mechanismus für `~/.finlai/.salt` implementieren.

---

### 2. RAM-Dumps

**Risiko:** Entschlüsselte Daten (API-Keys, Chat-Inhalte) liegen
kurzzeitig im Python-Prozess-Speicher. Bei gezielten Angriffen mit
physischem Speicher-Zugriff theoretisch auslesbar.

**Begründung akzeptiert:** Für eine Desktop-Anwendung ohne erhöhte
Privilege-Anforderungen ist dieses Risiko vertretbar.

---

### 3. Ollama Non-Localhost

**Risiko:** Wenn der User bewusst einen externen Server konfiguriert,
verlassen Chat-Daten den lokalen Rechner unverschlüsselt (ohne TLS
bei HTTP).

**Mitigiert durch:** Warn-Dialog bei Non-Localhost-URLs;
validate_url() mit allow_non_localhost=False als Standard.

---

### 4. DeepL Cloud-Service

**Risiko:** DeepL verarbeitet übersetzte Texte auf EU-Cloud-Servern.
Der User muss sich der Cloud-Natur des Services bewusst sein.

**Mitigiert durch:** Hinweis in der DeepL-Einstellungs-UI;
keine automatische Übersetzung sensibler Daten ohne User-Aktion.

---

### 5. PBKDF2 vs. Argon2

**Risiko:** PBKDF2-HMAC-SHA256 mit 480.000 Iterationen ist weniger
GPU-resistent als Argon2id.

**Begründung akzeptiert:** `cryptography`-Library unterstützt
PBKDF2 nativ und ist bereits als Abhängigkeit vorhanden.
Argon2 würde eine zusätzliche Abhängigkeit erfordern.

**Empfehlung:** Migration zu Argon2id in einer zukünftigen Version.

---

### 6. Keine Netzwerk-Isolierung

**Risiko:** Ein kompromittierter Ollama-Server könnte theoretisch
via `on_token`-Callbacks Daten aus der App exfiltrieren.

**Mitigiert durch:** `on_token` führt nur `str.append()` aus;
kein eval/exec auf Tokenwerten; QTextEdit rendert nur Markdown.

---

*Erstellt: 2026-03-20 | Autor: Patrick Riederich*
