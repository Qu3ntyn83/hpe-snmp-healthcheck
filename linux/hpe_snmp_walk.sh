#!/usr/bin/env bash
# =============================================================================
#  hpe_snmp_walk.sh  –  Kompletter SNMP-Walk für HPE ProLiant Server
#                       (iLO 4/5/6 mit AMS bzw. Insight Management Agents)
#
#  1. Führt einen vollständigen SNMP-Walk aus (Standard: .1.3.6.1 = alles)
#  2. Speichert den Rohwalk (numerisch) als Datei
#  3. Wertet alle bekannten Status-/Condition-OIDs der HPE-CPQ-MIBs
#     (Enterprise 232) aus und listet am Ende alle WARNUNGEN und FEHLER
#
#  Exit-Codes (Nagios/Icinga-kompatibel): 0=OK 1=WARN 2=CRIT 3=UNKNOWN
#
#  Voraussetzung: net-snmp (snmpbulkwalk/snmpwalk), awk
#     Debian/Ubuntu: apt install snmp      RHEL/Alma: dnf install net-snmp-utils
#
#  #Powerscripting – Torsten Weise – https://powerscripting.de
#  Version 1.0 – MIT-Lizenz
# =============================================================================
set -o pipefail

HOST=""; COMMUNITY="public"; SNMPVER="2c"
V3USER=""; V3LEVEL="authPriv"; V3AUTHPROTO="SHA"; V3AUTHPASS=""; V3PRIVPROTO="AES"; V3PRIVPASS=""
OUTDIR="."; INFILE=""; ROOT=".1.3.6.1"; TIMEOUT=5; RETRIES=2; NOCOLOR=0

usage() {
cat <<EOF
Verwendung:
  $(basename "$0") -H <host> [Optionen]        Walk ausführen + auswerten
  $(basename "$0") -f <walkdatei>              Vorhandenen Walk nur auswerten

Optionen:
  -H <host>     Hostname/IP des iLO bzw. Servers
  -v <1|2c|3>   SNMP-Version (Standard: 2c)
  -c <comm>     Community (v1/v2c, Standard: public)
  -u <user>     SNMPv3 Benutzer
  -l <level>    SNMPv3 Level: noAuthNoPriv|authNoPriv|authPriv (Standard: authPriv)
  -a <proto>    SNMPv3 Auth-Protokoll: MD5|SHA|SHA-256 ... (Standard: SHA)
  -A <pass>     SNMPv3 Auth-Passwort
  -x <proto>    SNMPv3 Priv-Protokoll: DES|AES (Standard: AES)
  -X <pass>     SNMPv3 Priv-Passwort
  -r <oid>      Startpunkt des Walks (Standard: .1.3.6.1 = komplett,
                nur HPE: .1.3.6.1.4.1.232)
  -t <sek>      Timeout pro Request (Standard: 5)
  -o <dir>      Ausgabeverzeichnis (Standard: .)
  -f <datei>    Kein Walk, vorhandene Walkdatei auswerten
                (Format: snmpwalk -On -Oe -Oq)
  -n            Keine Farben
  -h            Hilfe

Beispiele:
  $(basename "$0") -H 10.0.10.21 -c public
  $(basename "$0") -H ilo-srv01.kunde.local -v 3 -u monitor -A 'AuthPW' -X 'PrivPW'
  $(basename "$0") -f walk_10.0.10.21_20261030-1230.txt
EOF
}

while getopts "H:c:v:u:l:a:A:x:X:o:f:r:t:nh" opt; do
  case $opt in
    H) HOST=$OPTARG ;;      c) COMMUNITY=$OPTARG ;;   v) SNMPVER=$OPTARG ;;
    u) V3USER=$OPTARG ;;    l) V3LEVEL=$OPTARG ;;     a) V3AUTHPROTO=$OPTARG ;;
    A) V3AUTHPASS=$OPTARG ;; x) V3PRIVPROTO=$OPTARG ;; X) V3PRIVPASS=$OPTARG ;;
    o) OUTDIR=$OPTARG ;;    f) INFILE=$OPTARG ;;      r) ROOT=$OPTARG ;;
    t) TIMEOUT=$OPTARG ;;   n) NOCOLOR=1 ;;
    h) usage; exit 0 ;;     *) usage; exit 3 ;;
  esac
done

[[ -z $HOST && -z $INFILE ]] && { usage; exit 3; }
[[ -t 1 ]] || NOCOLOR=1
mkdir -p "$OUTDIR" || exit 3
TS=$(date +%Y%m%d-%H%M)

# -----------------------------------------------------------------------------
# 1. SNMP-Walk
# -----------------------------------------------------------------------------
if [[ -n $INFILE ]]; then
  [[ -r $INFILE ]] || { echo "Datei nicht lesbar: $INFILE" >&2; exit 3; }
  RAW=$INFILE
  TAG=$(basename "$INFILE" .txt)
else
  if [[ $SNMPVER == 3 ]]; then
    [[ -z $V3USER ]] && { echo "SNMPv3: -u <user> fehlt" >&2; exit 3; }
    AUTH=(-v3 -u "$V3USER" -l "$V3LEVEL")
    [[ $V3LEVEL != noAuthNoPriv ]] && AUTH+=(-a "$V3AUTHPROTO" -A "$V3AUTHPASS")
    [[ $V3LEVEL == authPriv ]]     && AUTH+=(-x "$V3PRIVPROTO" -X "$V3PRIVPASS")
  else
    AUTH=(-v "$SNMPVER" -c "$COMMUNITY")
  fi

  if [[ $SNMPVER == 1 ]]; then WALK=(snmpwalk); else WALK=(snmpbulkwalk -Cr50); fi
  command -v "${WALK[0]}" >/dev/null || { echo "${WALK[0]} nicht gefunden – net-snmp installieren." >&2; exit 3; }

  RAW="$OUTDIR/walk_${HOST}_${TS}.txt"
  TAG="${HOST}_${TS}"
  echo "SNMP-Walk ${HOST} ab ${ROOT} (SNMP v${SNMPVER}) ..." >&2
  START=$(date +%s)
  # -On numerische OIDs | -Oe Enums als Zahl | -Oq ohne Typ | -Ot Timeticks roh
  # -m "" verhindert MIB-Parserwarnungen (Auswertung arbeitet numerisch)
  "${WALK[@]}" "${AUTH[@]}" -t "$TIMEOUT" -r "$RETRIES" -m "" -On -Oe -Oq -Ot \
      "$HOST" "$ROOT" > "$RAW" 2> "$RAW.err"
  RC=$?
  CNT=$(grep -c '^\.' "$RAW")
  echo "Walk beendet: ${CNT} OIDs in $(( $(date +%s) - START ))s -> $RAW" >&2
  if [[ $RC -ne 0 && $CNT -eq 0 ]]; then
    echo "SNMP-Fehler: $(head -n3 "$RAW.err")" >&2; exit 3
  fi
  [[ -s "$RAW.err" ]] || rm -f "$RAW.err"
fi

# -----------------------------------------------------------------------------
# 2. Auswertung
# -----------------------------------------------------------------------------
read -r -d '' AWKPROG <<'AWK'
# ---------- Enum-Tabellen:  wert:name:schwere  (O=ok W=warn C=crit I=info/n.a.)
function defmap(m, spec,   a, k, i, p) {
  k = split(spec, a, ",")
  for (i = 1; i <= k; i++) { split(a[i], p, ":"); en[m, p[1]] = p[2]; es[m, p[1]] = p[3] }
}
function rule(kind, pfx, label, m, ctx) {
  nr++; rk[nr] = kind; rp[nr] = E pfx; rl[nr] = label; rm[nr] = m; rc[nr] = ctx
}
function enumtxt(m, v) { return ((m, v) in en) ? en[m, v] : v }

# ---------- Kontext je Tabellenzeile (Sensorname, Disk-Slot, ...)
function ctxinfo(c, idx,   s, b, x) {
  if (c == "TEMP") {
    b = E ".6.2.6.8.1."; s = "Sensor " idx
    if ((b "3." idx) in val) s = s " (" enumtxt("LOC", val[b "3." idx]) ")"
    if ((b "4." idx) in val) s = s ", " val[b "4." idx] "°C"
    if ((b "5." idx) in val && val[b "5." idx] + 0 > 0) s = s " / Schwelle " val[b "5." idx] "°C"
    return s
  }
  if (c == "FAN") {
    b = E ".6.2.6.7.1."; s = "Lüfter " idx
    if ((b "3." idx) in val) s = s " (" enumtxt("LOC", val[b "3." idx]) ")"
    return s
  }
  if (c == "PHY") {
    b = E ".3.2.5.1.1."; s = "Disk " idx
    if ((b "64." idx) in val && val[b "64." idx] != "") s = s " [" val[b "64." idx] "]"
    if ((b "3." idx)  in val && val[b "3." idx]  != "") s = s " " val[b "3." idx]
    return s
  }
  if (c == "PSU")  return "Netzteil " idx
  if (c == "LOG")  return "Log. Laufwerk " idx
  if (c == "CTRL") return "Controller " idx
  if (c == "ACC")  return "Cache-Modul " idx
  if (c == "MEM")  return "DIMM " idx
  if (c == "CPU")  return "CPU " idx
  return idx
}

function evalr(label, m, c, o, idx,   v, s, t) {
  v = val[o]; checked++
  if ((m, v) in es) { s = es[m, v]; t = en[m, v] "(" v ")" } else { s = "W"; t = "unbekannt(" v ")" }
  if (s == "O") { okc++; return }
  if (s == "I") { infc++; return }
  if (s == "C") crit++; else warn++
  nres++; rs[nres] = s; rlab[nres] = label; rval[nres] = t; roid[nres] = o
  rinst[nres] = (idx == "") ? "-" : ctxinfo(c, idx)
}

BEGIN {
  E = ".1.3.6.1.4.1.232"
  if (nocolor) { cR = cY = cG = cB = c0 = "" }
  else { cR = "\033[1;31m"; cY = "\033[1;33m"; cG = "\033[1;32m"; cB = "\033[1m"; c0 = "\033[0m" }

  defmap("COND",  "1:other:I,2:ok:O,3:degraded:W,4:failed:C")
  defmap("CPU",   "1:unknown:I,2:ok:O,3:degraded:W,4:failed:C,5:disabled:W")
  defmap("RED",   "1:other:I,2:notRedundant:W,3:redundant:O")
  defmap("BATT",  "1:other:I,2:ok:O,3:recharging:W,4:failed:C,5:degraded:W,6:notPresent:I,7:capacitorFailed:C")
  defmap("SMART", "1:other:I,2:ok:O,3:replaceDrive:C,4:replaceDriveSSDWearOut:W")
  defmap("PHY",   "1:other:I,2:ok:O,3:failed:C,4:predictiveFailure:W,5:erasing:W,6:eraseDone:W,7:eraseQueued:W,8:ssdWearOut:W,9:notAuthenticated:W")
  defmap("LOGD",  "1:other:I,2:ok:O,3:failed:C,4:unconfigured:W,5:recovering:W,6:readyForRebuild:W,7:rebuilding:W,8:wrongDrive:C,9:badConnect:C,10:overheating:C,11:shutdown:C,12:expanding:W,13:notAvailable:C,14:queuedForExpansion:W,15:multipathAccessDegraded:W,16:erasing:W,17:predictiveSpareRebuildReady:W")
  defmap("PSUST", "1:noError:O,2:generalFailure:C,3:bistFailure:C,4:fanFailure:C,5:tempFailure:C,6:interlockOpen:C,7:epromFailed:C,8:vrefFailed:C,9:dacFailed:C,10:ramTestFailed:C,11:voltageChannelFailed:C,12:orringdiodeFailed:C,13:brownOut:C,14:giveupOnStartup:C,15:nvramInvalid:C,16:calibrationTableInvalid:C,17:noPowerInput:C")
  defmap("LOC",   "1:other,2:unknown,3:system,4:systemBoard,5:ioBoard,6:cpu,7:memory,8:storage,9:removableMedia,10:powerSupply,11:ambient,12:chassis,13:bridgeCard")

  # Subsysteme für die generischen cpq*MibCondition-OIDs (232.<n>.1.3.0)
  split("1:Standard-Equipment (cpqSe),2:Systeminfo (cpqSi),3:Smart Array (cpqDa),5:SCSI/SAS (cpqScsi/cpqSas),6:Health gesamt (cpqHe),8:Storage-Systeme (cpqSs),9:iLO / Remote Insight (cpqSm2),11:Host-OS (cpqHo),14:IDE/SATA (cpqIde),16:Fibre Channel (cpqFca),18:Netzwerk / NIC (cpqNic),22:Rack (cpqRack)", sl, ",")
  for (i in sl) { split(sl[i], p, ":"); subname[p[1]] = p[2] }

  # ---------- Regeln:  S=Skalar  T=Tabellenspalte
  rule("S", ".6.2.6.1.0",          "Thermik gesamt",            "COND", "")
  rule("S", ".6.2.6.3.0",          "Temperaturstatus",          "COND", "")
  rule("S", ".6.2.6.4.0",          "Systemlüfter-Status",       "COND", "")
  rule("S", ".6.2.6.5.0",          "CPU-Lüfter-Status",         "COND", "")
  rule("T", ".6.2.6.8.1.6",        "Temperatursensor",          "COND", "TEMP")
  rule("T", ".6.2.6.7.1.9",        "Lüfter",                    "COND", "FAN")
  rule("S", ".6.2.9.1.0",          "Netzteile gesamt",          "COND", "")
  rule("T", ".6.2.9.3.1.4",        "Netzteil Condition",        "COND", "PSU")
  rule("T", ".6.2.9.3.1.5",        "Netzteil Status",           "PSUST","PSU")
  rule("T", ".6.2.9.3.1.9",        "Netzteil Redundanz",        "RED",  "PSU")
  rule("S", ".6.2.14.4.0",         "Arbeitsspeicher gesamt",    "COND", "")
  rule("T", ".6.2.14.13.1.20",     "Speichermodul",             "COND", "MEM")
  rule("S", ".6.2.11.2.0",         "IML (Integrated Mgmt Log)", "COND", "")
  rule("T", ".1.2.2.1.1.6",        "Prozessor",                 "CPU",  "CPU")
  rule("T", ".3.2.2.1.1.6",        "Array-Controller",          "COND", "CTRL")
  rule("T", ".3.2.2.1.1.12",       "Controller-Board",          "COND", "CTRL")
  rule("T", ".3.2.2.2.1.9",        "Controller-Cache",          "COND", "ACC")
  rule("T", ".3.2.2.2.1.6",        "Cache-Batterie/Kondensator","BATT", "ACC")
  rule("T", ".3.2.3.1.1.4",        "Logisches Laufwerk Status", "LOGD", "LOG")
  rule("T", ".3.2.3.1.1.11",       "Logisches Laufwerk",        "COND", "LOG")
  rule("T", ".3.2.5.1.1.6",        "Physische Disk Status",     "PHY",  "PHY")
  rule("T", ".3.2.5.1.1.37",       "Physische Disk",            "COND", "PHY")
  rule("T", ".3.2.5.1.1.57",       "Disk S.M.A.R.T.",           "SMART","PHY")
}

/^\./ {
  o = $1; v = $0; sub(/^[^ ]+ ?/, "", v); gsub(/^"|"$/, "", v)
  if (!(o in val)) order[++n] = o
  val[o] = v
  if (index(o, E ".") == 1) hpe++
}

END {
  if (n == 0) { print "UNKNOWN: Walk enthält keine OIDs."; exit 3 }

  # ---------- Kopfdaten
  S = ".1.3.6.1.2.1.1."
  print cB "============================================================================" c0
  print cB " HPE ProLiant SNMP-Auswertung" c0
  print cB "============================================================================" c0
  if ((S "5.0") in val)          printf " Hostname     : %s\n", val[S "5.0"]
  if ((E ".2.2.4.2.0") in val)   printf " Modell       : %s\n", val[E ".2.2.4.2.0"]
  if ((E ".2.2.2.1.0") in val)   printf " Seriennummer : %s\n", val[E ".2.2.2.1.0"]
  if ((E ".1.2.6.1.0") in val)   printf " System-ROM   : %s\n", val[E ".1.2.6.1.0"]
  if ((S "1.0") in val)          printf " sysDescr     : %s\n", substr(val[S "1.0"], 1, 90)
  if ((S "3.0") in val && val[S "3.0"] ~ /^[0-9]+$/) {
    t = int(val[S "3.0"] / 100)
    printf " Uptime Agent : %dd %02dh %02dm\n", int(t/86400), int(t%86400/3600), int(t%3600/60)
  }
  if ((E ".6.1.3.0") in val)     printf " Health gesamt: %s\n", enumtxt("COND", val[E ".6.1.3.0"])
  printf " OIDs im Walk : %d (davon HPE/CPQ: %d)\n", n, hpe

  if (hpe == 0) {
    print ""
    print cY "UNKNOWN: Keine HPE-CPQ-OIDs (1.3.6.1.4.1.232) gefunden." c0
    print "  -> iLO: SNMP aktiv? 'Agentless Management' / AMS im OS installiert?"
    print "  -> Gen8/9 mit Insight Agents: hp-snmp-agents installiert und gestartet?"
    exit 3
  }

  # ---------- Regeln auswerten
  for (i = 1; i <= nr; i++) {
    if (rk[i] == "S") { if (rp[i] in val) evalr(rl[i], rm[i], rc[i], rp[i], ""); continue }
    pl = length(rp[i]) + 1
    for (j = 1; j <= n; j++) {
      o = order[j]
      if (substr(o, 1, pl) == rp[i] ".") evalr(rl[i], rm[i], rc[i], o, substr(o, pl + 1))
    }
  }
  # ---------- generisch: alle Subsystem-Conditions (cpq*MibCondition)
  for (j = 1; j <= n; j++) {
    o = order[j]
    if (o ~ /^\.1\.3\.6\.1\.4\.1\.232\.[0-9]+\.1\.3\.0$/) {
      split(o, p, ".")
      evalr("Subsystem " ((p[9] in subname) ? subname[p[9]] : p[9]), "COND", "", o, "")
    }
  }

  # ---------- Ergebnis
  print ""
  printf " Geprüfte Status-OIDs: %d  |  %sOK: %d%s  |  %sWARN: %d%s  |  %sCRIT: %d%s  |  n.a.: %d\n",
         checked, cG, okc, c0, cY, warn, c0, cR, crit, c0, infc
  print ""
  if (nres == 0) {
    print cG " Keine Warnungen oder Fehler gefunden." c0
    exit 0
  }
  print cB " WERTE MIT FEHLER / WARNUNG" c0
  print " ----------------------------------------------------------------------------"
  printf " %-5s %-33s %-46s %-24s %s\n", "STUFE", "KOMPONENTE", "INSTANZ", "WERT", "OID"
  print " ----------------------------------------------------------------------------"
  for (pass = 1; pass <= 2; pass++) {
    want = (pass == 1) ? "C" : "W"
    for (k = 1; k <= nres; k++) {
      if (rs[k] != want) continue
      col = (want == "C") ? cR : cY
      printf " %s%-5s%s %-33s %-46s %-24s %s\n", col, (want == "C" ? "CRIT" : "WARN"), c0,
             rlab[k], rinst[k], rval[k], roid[k]
    }
  }
  exit (crit > 0) ? 2 : 1
}
AWK

OUT=$(awk -v nocolor="$NOCOLOR" "$AWKPROG" "$RAW")
RC=$?
printf '%s\n' "$OUT"
REPORT="$OUTDIR/report_${TAG}.txt"
printf '%s\n' "$OUT" | sed 's/\x1b\[[0-9;]*m//g' > "$REPORT"
echo "" ; echo "Report: $REPORT" ; [[ -z $INFILE ]] && echo "Rohwalk: $RAW"
exit $RC
