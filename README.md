# HPE ProLiant SNMP-Healthcheck

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-unterst%C3%BCtzen-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/quentyn83)

Liest den Hardware-Status von HPE ProLiant Servern über das iLO per SNMP aus und zeigt am Ende alle Werte, die auf **Fehler** oder **Warnung** stehen. Es gibt das Tool in zwei Varianten:

- **Windows:** grafische Oberfläche, ohne Installation und ohne Zusatzmodule
- **Linux:** Bash-Skript auf Basis von net-snmp

Teil von [#Powerscripting](https://powerscripting.de) – *Elevate. Automate. Innovate.*

## Was geprüft wird

Ausgewertet werden die HPE-CPQ-MIBs (Enterprise-OID `1.3.6.1.4.1.232`):

| Bereich | Werte |
| --- | --- |
| Gesamt | Health-Status, Status aller Subsysteme (iLO, NIC, SAS, Fibre Channel …) |
| Thermik | Temperatursensoren mit Ort, aktuellem Wert und Schwelle; System- und CPU-Lüfter |
| Strom | Netzteile (Condition, Fehlerstatus, Redundanz) |
| System | Prozessoren, Speichermodule (DIMMs), Integrated Management Log (IML) |
| Storage | Smart-Array-Controller, Cache, Batterie/Kondensator, logische Laufwerke (Rebuild, degraded …), physische Disks mit Slot, Modell und S.M.A.R.T. |

Jeder Wert wird als **OK**, **Warnung**, **Kritisch** oder **nicht zutreffend** eingestuft. Fehler und Warnungen erscheinen mit deutscher Beschreibung und einer Handlungsempfehlung.

## Windows

**Voraussetzungen:** Windows 10/11 oder Windows Server 2012 R2 und neuer (PowerShell 5.1, ist überall vorhanden). Keine Admin-Rechte nötig.

1. Repository als ZIP herunterladen (**Code → Download ZIP**) und entpacken. Vorher in den Dateieigenschaften des ZIP „Zulassen“ anhaken.
2. `windows/HPE-SNMP-Healthcheck.cmd` doppelklicken.
3. iLO-IP eintragen (mehrere Server mit Komma), SNMP-Version und Community bzw. SNMPv3-Zugangsdaten angeben, **Walk starten**.

Die Oberfläche zeigt die Befunde gruppiert je Server und farbig markiert. Ein Doppelklick auf eine Zeile öffnet den HTML-Bericht. Mit Rechtsklick lassen sich Zeilen kopieren, etwa für ein Ticket.

**Eigenschaften**

- SNMP v1, v2c und v3 (MD5 / SHA / SHA-256, AES-128 / DES). Die SNMP-Engine ist direkt im Skript enthalten, net-snmp wird nicht gebraucht.
- Der Walk läuft im Hintergrund und lässt sich abbrechen.
- Umfang wählbar: komplett (`.1.3.6.1`) oder nur der HPE-Zweig (schneller).
- Die Oberfläche passt sich der Bildschirmskalierung an (High-DPI).

**Ergebnis je Server** (Ordner `Reports` neben dem Tool):

| Datei | Inhalt |
| --- | --- |
| `walk_<host>_<zeit>.txt` | kompletter Walk im net-snmp-Format (`-On -Oq`) |
| `report_<host>_<zeit>.txt` | Auswertung als Text |
| `report_<host>_<zeit>.html` | Bericht zum Weitergeben, druckbar |

**Kommandozeile** – mit Parametern läuft dasselbe Tool ohne Oberfläche, z. B. für Monitoring oder Aufgabenplanung:

```bat
HPE-SNMP-Healthcheck.cmd -Target 10.0.10.21,10.0.10.22 -Community public -Customer "Muster GmbH"
HPE-SNMP-Healthcheck.cmd -Target ilo-srv01 -Version 3 -User monitor -AuthPassword "xxx" -PrivPassword "yyy"
HPE-SNMP-Healthcheck.cmd -AnalyzeFile .\Reports\walk_10.0.10.21_20261030-124500.txt
```

Weitere Parameter: `-Root`, `-OutDir`, `-Port`, `-TimeoutSec`, `-Retries`, `-MaxRepetitions`, `-AuthProtocol`, `-PrivProtocol`, `-SecLevel`.

## Linux

Benötigt `net-snmp` (`apt install snmp` bzw. `dnf install net-snmp-utils`).

```bash
./linux/hpe_snmp_walk.sh -H 10.0.10.21 -c public
./linux/hpe_snmp_walk.sh -H ilo-srv01 -v 3 -u monitor -A 'AuthPW' -X 'PrivPW'
./linux/hpe_snmp_walk.sh -H 10.0.10.21 -r .1.3.6.1.4.1.232     # nur HPE-Zweig
./linux/hpe_snmp_walk.sh -f walk_10.0.10.21_20261030-1230.txt    # vorhandenen Walk auswerten
```

Walk-Dateien beider Varianten sind untereinander austauschbar.

## Exit-Codes

Beide Varianten liefern Nagios-/Icinga-kompatible Exit-Codes:

| Code | Bedeutung |
| --- | --- |
| 0 | OK |
| 1 | Warnung |
| 2 | Kritisch |
| 3 | Fehler / unbekannt |

## Hinweise

- **SNMP im iLO aktivieren:** iLO 5/6 unter *Sicherheit → SNMP* bzw. *Management → SNMP-Einstellungen*, außerdem UDP 161 in der Firewall freigeben.
- **Gen10 und neuer:** Das iLO liefert die Hardware-Werte nur vollständig, wenn im Betriebssystem der **Agentless Management Service (AMS)** läuft (Windows: AMS aus dem SPP; ESXi: HPE-Custom-Image bzw. AMS-VIB). Fehlen die HPE-Werte, meldet das Tool „unbekannt“.
- Ein Server mit nur einem Netzteil meldet bewusst „nicht redundant“.
- Eine IML-Warnung bleibt stehen, bis die Einträge im iLO als repariert markiert oder gelöscht wurden.
- Bei aktivem AppLocker oder Constrained Language Mode kann das Kompilieren der SNMP-Engine (`Add-Type`) gesperrt sein.

## Unterstützen

Wenn dir das Projekt hilft und du mir einen Kaffee ausgeben möchtest, freue ich mich sehr:

<a href="https://buymeacoffee.com/quentyn83"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="45"></a>

## Lizenz

[MIT](LICENSE) – Torsten Weise, [powerscripting.de](https://powerscripting.de)
