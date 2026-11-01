<#
.SYNOPSIS
    HPE ProLiant SNMP-Healthcheck (GUI + Kommandozeile)
    Kompletter SNMP-Walk über das iLO und Auswertung aller Fehler-/Warnungswerte.

.DESCRIPTION
    Ohne Parameter startet die grafische Oberfläche.
    Mit -Target / -AnalyzeFile läuft das Tool auf der Kommandozeile.

    Keine externen Abhängigkeiten: SNMP v1 / v2c / v3 (MD5, SHA, SHA256 /
    AES-128, DES) ist direkt in .NET implementiert.

    Ergebnis je Server (Ordner "Reports"):
      walk_<host>_<zeit>.txt     kompletter Walk (net-snmp-Format -On -Oq)
      report_<host>_<zeit>.txt   Auswertung als Text
      report_<host>_<zeit>.html  Kundenbericht

.EXAMPLE
    .\HPE-SNMP-Walk.ps1
.EXAMPLE
    .\HPE-SNMP-Walk.ps1 -Target 10.0.10.21,10.0.10.22 -Community public -Customer "Muster GmbH"
.EXAMPLE
    .\HPE-SNMP-Walk.ps1 -Target ilo-srv01 -Version 3 -User monitor -AuthPassword 'xxx' -PrivPassword 'yyy'

.NOTES
    #Powerscripting – Torsten Weise – https://powerscripting.de
    Version 2.1 (2026-11) – MIT-Lizenz
    Exit-Codes (Kommandozeile): 0 = OK, 1 = Warnung, 2 = Kritisch, 3 = Fehler
#>
[CmdletBinding()]
param(
    [string[]]$Target,
    [ValidateSet('1', '2c', '3')][string]$Version = '2c',
    [string]$Community = 'public',
    [string]$User,
    [ValidateSet('noAuthNoPriv', 'authNoPriv', 'authPriv')][string]$SecLevel = 'authPriv',
    [ValidateSet('MD5', 'SHA', 'SHA256')][string]$AuthProtocol = 'SHA',
    [string]$AuthPassword,
    [ValidateSet('AES', 'DES')][string]$PrivProtocol = 'AES',
    [string]$PrivPassword,
    [string]$Root = '.1.3.6.1',
    [string]$Customer,
    [string]$OutDir,
    [int]$Port = 161,
    [int]$TimeoutSec = 3,
    [int]$Retries = 2,
    [int]$MaxRepetitions = 25,
    [string]$AnalyzeFile,
    [switch]$Gui
)

$ToolVersion = '2.1'
$ErrorActionPreference = 'Stop'
$GuiMode = $Gui -or (-not $Target -and -not $AnalyzeFile)

# =============================================================================
#  SNMP-Engine (C#, wird zur Laufzeit kompiliert – C# 5 / .NET Framework 4.x)
# =============================================================================
$CSharp = @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace PsSnmp
{
    public static class Native
    {
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();
    }

    public class VarBind
    {
        public string Oid;
        public byte Type;
        public string Value;
        public bool IsText;
    }

    public class PduResult
    {
        public byte Type;
        public int RequestId;
        public int ErrorStatus;
        public int ErrorIndex;
        public List<VarBind> VarBinds = new List<VarBind>();
    }

    public class Node
    {
        public byte Tag;
        public byte[] Data;
    }

    public static class Ber
    {
        public static byte[] Cat(params byte[][] parts)
        {
            int n = 0;
            foreach (byte[] p in parts) n += p.Length;
            byte[] r = new byte[n];
            int o = 0;
            foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
            return r;
        }

        public static byte[] Len(int n)
        {
            if (n < 0x80) return new byte[] { (byte)n };
            List<byte> b = new List<byte>();
            while (n > 0) { b.Insert(0, (byte)(n & 0xFF)); n >>= 8; }
            b.Insert(0, (byte)(0x80 | b.Count));
            return b.ToArray();
        }

        public static int HdrLen(int contentLen) { return 1 + Len(contentLen).Length; }

        public static byte[] Tlv(byte tag, byte[] content)
        {
            return Cat(new byte[] { tag }, Len(content.Length), content);
        }

        public static byte[] Int(long v)
        {
            List<byte> b = new List<byte>();
            while (true)
            {
                byte x = (byte)(v & 0xFF);
                b.Insert(0, x);
                v >>= 8;
                if ((v == 0 && (x & 0x80) == 0) || (v == -1 && (x & 0x80) != 0)) break;
            }
            return Tlv(0x02, b.ToArray());
        }

        public static byte[] Oct(byte[] d) { return Tlv(0x04, d ?? new byte[0]); }

        public static byte[] Oid(string oid)
        {
            string[] p = oid.Trim().Trim('.').Split('.');
            if (p.Length < 2) throw new ArgumentException("Ungueltige OID: " + oid);
            List<byte> b = new List<byte>();
            b.AddRange(B128(ulong.Parse(p[0]) * 40 + ulong.Parse(p[1])));
            for (int i = 2; i < p.Length; i++) b.AddRange(B128(ulong.Parse(p[i])));
            return Tlv(0x06, b.ToArray());
        }

        static byte[] B128(ulong v)
        {
            List<byte> t = new List<byte>();
            t.Add((byte)(v & 0x7F));
            v >>= 7;
            while (v > 0) { t.Insert(0, (byte)((v & 0x7F) | 0x80)); v >>= 7; }
            return t.ToArray();
        }

        public static Node Read(byte[] buf, ref int pos)
        {
            if (pos + 2 > buf.Length) throw new FormatException("BER: unerwartetes Paketende");
            Node n = new Node();
            n.Tag = buf[pos++];
            int len = buf[pos++];
            if ((len & 0x80) != 0)
            {
                int c = len & 0x7F;
                if (c > 4) throw new FormatException("BER: Laengenfeld ungueltig");
                len = 0;
                for (int i = 0; i < c; i++) len = (len << 8) | buf[pos++];
            }
            if (len < 0 || pos + len > buf.Length) throw new FormatException("BER: Laenge ungueltig");
            n.Data = new byte[len];
            Buffer.BlockCopy(buf, pos, n.Data, 0, len);
            pos += len;
            return n;
        }

        public static Node Read(byte[] buf) { int p = 0; return Read(buf, ref p); }

        public static List<Node> Children(byte[] data)
        {
            List<Node> l = new List<Node>();
            int p = 0;
            while (p < data.Length) l.Add(Read(data, ref p));
            return l;
        }

        public static long ToInt(byte[] d)
        {
            long v = (d.Length > 0 && (d[0] & 0x80) != 0) ? -1 : 0;
            foreach (byte x in d) v = (v << 8) | x;
            return v;
        }

        public static ulong ToUInt(byte[] d)
        {
            ulong v = 0;
            foreach (byte x in d) v = (v << 8) | x;
            return v;
        }

        public static string ToOid(byte[] d)
        {
            StringBuilder sb = new StringBuilder();
            ulong v = 0;
            bool first = true;
            foreach (byte x in d)
            {
                v = (v << 7) | (ulong)(x & 0x7F);
                if ((x & 0x80) == 0)
                {
                    if (first)
                    {
                        ulong a = v < 40 ? 0UL : (v < 80 ? 1UL : 2UL);
                        sb.Append('.').Append(a).Append('.').Append(v - a * 40);
                        first = false;
                    }
                    else sb.Append('.').Append(v);
                    v = 0;
                }
            }
            return sb.ToString();
        }

        public static string Hex(byte[] d)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.Length; i++) { if (i > 0) sb.Append(' '); sb.Append(d[i].ToString("X2")); }
            return sb.ToString();
        }

        public static void Format(Node n, VarBind vb)
        {
            vb.Type = n.Tag;
            vb.IsText = false;
            switch (n.Tag)
            {
                case 0x02: vb.Value = ToInt(n.Data).ToString(); break;
                case 0x04: FormatOctet(n.Data, vb); break;
                case 0x05: vb.Value = ""; break;
                case 0x06: vb.Value = ToOid(n.Data); break;
                case 0x40:
                    vb.Value = n.Data.Length == 4
                        ? n.Data[0] + "." + n.Data[1] + "." + n.Data[2] + "." + n.Data[3]
                        : Hex(n.Data);
                    break;
                case 0x41: case 0x42: case 0x43: case 0x46: case 0x47:
                    vb.Value = ToUInt(n.Data).ToString(); break;
                case 0x80: vb.Value = "noSuchObject"; break;
                case 0x81: vb.Value = "noSuchInstance"; break;
                case 0x82: vb.Value = "endOfMibView"; break;
                default: vb.Value = Hex(n.Data); break;
            }
        }

        static void FormatOctet(byte[] d, VarBind vb)
        {
            int len = d.Length;
            while (len > 0 && d[len - 1] == 0) len--;
            string s = null;
            bool ok = (len > 0 || d.Length == 0);
            if (ok)
            {
                try { s = new UTF8Encoding(false, true).GetString(d, 0, len); }
                catch { ok = false; }
            }
            if (ok)
            {
                foreach (char ch in s)
                    if (char.IsControl(ch) && ch != '\r' && ch != '\n' && ch != '\t') { ok = false; break; }
            }
            if (ok)
            {
                vb.IsText = true;
                vb.Value = s.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            }
            else vb.Value = Hex(d);
        }

        public static int CompareOid(string a, string b)
        {
            string[] x = a.Trim('.').Split('.');
            string[] y = b.Trim('.').Split('.');
            int n = Math.Min(x.Length, y.Length);
            for (int i = 0; i < n; i++)
            {
                ulong p = ulong.Parse(x[i]), q = ulong.Parse(y[i]);
                if (p != q) return p < q ? -1 : 1;
            }
            return x.Length.CompareTo(y.Length);
        }
    }

    public class SnmpClient : IDisposable
    {
        public string Host;
        public int Port = 161;
        public int Version = 1;            // 0 = v1, 1 = v2c, 3 = v3
        public string Community = "public";
        public int TimeoutMs = 3000;
        public int Retries = 2;
        public int MaxRepetitions = 25;
        public volatile bool CancelRequested;

        public string User = "";
        public string Level = "authPriv";  // noAuthNoPriv | authNoPriv | authPriv
        public string AuthProto = "SHA";   // MD5 | SHA | SHA256
        public string AuthPass = "";
        public string PrivProto = "AES";   // AES | DES
        public string PrivPass = "";

        UdpClient udp;
        IPEndPoint ep;
        int reqId, msgId;
        byte[] engineId = new byte[0];
        int boots, timeBase;
        DateTime timeSync = DateTime.UtcNow;
        byte[] authKey, privKey;
        ulong aesSalt;
        uint desSalt;
        byte[] lastEngine = new byte[0];
        int lastBoots, lastTime;

        bool AuthOn { get { return Version == 3 && Level != "noAuthNoPriv"; } }
        bool PrivOn { get { return Version == 3 && Level == "authPriv"; } }

        void CheckCancel() { if (CancelRequested) throw new OperationCanceledException("Vom Benutzer abgebrochen"); }

        public void Open()
        {
            IPAddress[] addrs = Dns.GetHostAddresses(Host);
            if (addrs.Length == 0) throw new Exception("Host nicht aufloesbar: " + Host);
            IPAddress ip = addrs[0];
            foreach (IPAddress a in addrs) if (a.AddressFamily == AddressFamily.InterNetwork) { ip = a; break; }
            ep = new IPEndPoint(ip, Port);
            udp = new UdpClient(ip.AddressFamily);
            udp.Client.ReceiveTimeout = 500;
            try { udp.Client.IOControl((IOControlCode)(-1744830452), new byte[] { 0, 0, 0, 0 }, null); } catch { }
            Random r = new Random();
            reqId = r.Next(1, 1 << 30);
            msgId = r.Next(1, 1 << 30);
            aesSalt = ((ulong)(uint)r.Next() << 32) | (uint)r.Next();
            desSalt = (uint)r.Next();
            AuthProto = (AuthProto ?? "SHA").ToUpperInvariant().Replace("-", "");
            if (AuthProto == "SHA1") AuthProto = "SHA";
            PrivProto = (PrivProto ?? "AES").ToUpperInvariant().Replace("-", "");
            if (PrivProto == "AES128") PrivProto = "AES";
            if (Version == 3) Discover();
        }

        public void Dispose() { if (udp != null) { udp.Close(); udp = null; } }

        int NextReqId() { reqId = (reqId % 2000000000) + 1; return reqId; }

        // ---------------------------------------------------------------- Transport
        byte[] Exchange(byte[] req, Func<byte[], bool> match)
        {
            for (int attempt = 0; attempt <= Retries; attempt++)
            {
                CheckCancel();
                udp.Send(req, req.Length, ep);
                DateTime deadline = DateTime.UtcNow.AddMilliseconds(TimeoutMs);
                while (DateTime.UtcNow < deadline)
                {
                    CheckCancel();
                    byte[] resp;
                    try { IPEndPoint from = null; resp = udp.Receive(ref from); }
                    catch (SocketException ex)
                    {
                        if (ex.SocketErrorCode == SocketError.TimedOut) continue;
                        break;
                    }
                    if (match(resp)) return resp;
                }
            }
            throw new TimeoutException("Keine Antwort von " + Host + " (" + (Retries + 1) + " Versuche a " + (TimeoutMs / 1000) + " s)");
        }

        static byte[] BuildPdu(byte type, int rid, int a, int b, string[] oids)
        {
            List<byte> vbs = new List<byte>();
            foreach (string o in oids) vbs.AddRange(Ber.Tlv(0x30, Ber.Cat(Ber.Oid(o), new byte[] { 0x05, 0x00 })));
            return Ber.Tlv(type, Ber.Cat(Ber.Int(rid), Ber.Int(a), Ber.Int(b), Ber.Tlv(0x30, vbs.ToArray())));
        }

        static PduResult ParsePdu(Node pdu)
        {
            PduResult r = new PduResult();
            r.Type = pdu.Tag;
            List<Node> c = Ber.Children(pdu.Data);
            r.RequestId = (int)Ber.ToInt(c[0].Data);
            r.ErrorStatus = (int)Ber.ToInt(c[1].Data);
            r.ErrorIndex = (int)Ber.ToInt(c[2].Data);
            foreach (Node vbn in Ber.Children(c[3].Data))
            {
                List<Node> v = Ber.Children(vbn.Data);
                VarBind vb = new VarBind();
                vb.Oid = Ber.ToOid(v[0].Data);
                Ber.Format(v[1], vb);
                r.VarBinds.Add(vb);
            }
            return r;
        }

        // ---------------------------------------------------------------- Public API
        public PduResult Get(params string[] oids) { return Request(0xA0, oids, 0, 0); }

        public PduResult Request(byte pduType, string[] oids, int nonRep, int maxRep)
        {
            if (Version != 3)
            {
                int rid = NextReqId();
                byte[] pdu = BuildPdu(pduType, rid, nonRep, maxRep, oids);
                byte[] msg = Ber.Tlv(0x30, Ber.Cat(Ber.Int(Version), Ber.Oct(Encoding.ASCII.GetBytes(Community ?? "")), pdu));
                byte[] resp = Exchange(msg, delegate (byte[] raw)
                {
                    try
                    {
                        List<Node> c = Ber.Children(Ber.Read(raw).Data);
                        return c.Count >= 3 && (int)Ber.ToInt(Ber.Children(c[2].Data)[0].Data) == rid;
                    }
                    catch { return false; }
                });
                return ParsePdu(Ber.Children(Ber.Read(resp).Data)[2]);
            }

            for (int attempt = 0; attempt < 4; attempt++)
            {
                int rid = NextReqId();
                byte[] pdu = BuildPdu(pduType, rid, nonRep, maxRep, oids);
                int mid;
                byte[] msg = BuildV3(pdu, AuthOn, PrivOn, out mid, false);
                byte[] resp = Exchange(msg, delegate (byte[] raw) { return MatchV3(raw, mid); });
                PduResult r = ParseV3(resp);
                if (r.Type == 0xA8) { HandleReport(r); continue; }
                return r;
            }
            throw new Exception("SNMPv3: Zeitsynchronisation mit dem Agent fehlgeschlagen");
        }

        public List<VarBind> Walk(string root, Action<int> progress)
        {
            root = "." + root.Trim().Trim('.');
            string prefix = root + ".";
            string cur = root;
            List<VarBind> res = new List<VarBind>();
            int maxRep = Math.Max(1, MaxRepetitions);
            while (true)
            {
                CheckCancel();
                PduResult r;
                try
                {
                    r = Version == 0
                        ? Request(0xA1, new string[] { cur }, 0, 0)
                        : Request(0xA5, new string[] { cur }, 0, maxRep);
                }
                catch (TimeoutException)
                {
                    if (Version != 0 && maxRep > 5) { maxRep = Math.Max(5, maxRep / 2); continue; }
                    throw;
                }
                if (r.ErrorStatus == 1 && Version != 0 && maxRep > 1) { maxRep = Math.Max(1, maxRep / 2); continue; }
                if (r.ErrorStatus == 2 && Version == 0) break;
                if (r.ErrorStatus != 0) throw new Exception("SNMP-Fehler errorStatus=" + r.ErrorStatus + " bei " + cur);
                if (r.VarBinds.Count == 0) break;
                bool done = false;
                foreach (VarBind vb in r.VarBinds)
                {
                    if (vb.Type == 0x82 || !vb.Oid.StartsWith(prefix, StringComparison.Ordinal)) { done = true; break; }
                    if (Ber.CompareOid(vb.Oid, cur) <= 0) { done = true; break; }
                    cur = vb.Oid;
                    if (vb.Type == 0x80 || vb.Type == 0x81) continue;
                    res.Add(vb);
                }
                if (progress != null) progress(res.Count);
                if (done) break;
            }
            return res;
        }

        // ---------------------------------------------------------------- SNMPv3 / USM
        void Discover()
        {
            int mid;
            byte[] pdu = BuildPdu(0xA0, NextReqId(), 0, 0, new string[0]);
            byte[] msg = BuildV3(pdu, false, false, out mid, true);
            byte[] resp = Exchange(msg, delegate (byte[] raw) { return MatchV3(raw, mid); });
            ParseV3(resp);
            if (lastEngine.Length == 0) throw new Exception("SNMPv3: Agent hat keine EngineID geliefert");
            engineId = lastEngine;
            boots = lastBoots;
            timeBase = lastTime;
            timeSync = DateTime.UtcNow;
            DeriveKeys();
        }

        void DeriveKeys()
        {
            if (AuthOn)
            {
                if (string.IsNullOrEmpty(AuthPass)) throw new Exception("SNMPv3: Auth-Passwort fehlt");
                authKey = PassToKey(AuthProto, AuthPass, engineId);
            }
            if (PrivOn)
            {
                if (string.IsNullOrEmpty(PrivPass)) throw new Exception("SNMPv3: Privacy-Passwort fehlt");
                privKey = PassToKey(AuthProto, PrivPass, engineId);
            }
        }

        static HashAlgorithm NewHash(string proto)
        {
            if (proto == "MD5") return MD5.Create();
            if (proto == "SHA256") return SHA256.Create();
            return SHA1.Create();
        }

        static byte[] PassToKey(string proto, string pass, byte[] engine)
        {
            byte[] pw = Encoding.UTF8.GetBytes(pass);
            using (HashAlgorithm h = NewHash(proto))
            {
                byte[] buf = new byte[1048576];
                for (int i = 0; i < buf.Length; i++) buf[i] = pw[i % pw.Length];
                byte[] ku = h.ComputeHash(buf);
                return h.ComputeHash(Ber.Cat(ku, engine, ku));
            }
        }

        int MacLen { get { return AuthProto == "SHA256" ? 24 : 12; } }

        byte[] Hmac(byte[] data)
        {
            HMAC h;
            if (AuthProto == "MD5") h = new HMACMD5(authKey);
            else if (AuthProto == "SHA256") h = new HMACSHA256(authKey);
            else h = new HMACSHA1(authKey);
            using (h) { return h.ComputeHash(data); }
        }

        int CurTime() { return timeBase + (int)(DateTime.UtcNow - timeSync).TotalSeconds; }

        byte[] BuildV3(byte[] pdu, bool auth, bool priv, out int mid, bool discovery)
        {
            msgId = (msgId % 2000000000) + 1;
            mid = msgId;
            byte flags = (byte)((auth ? 1 : 0) | (priv ? 2 : 0) | 4);
            byte[] eng = discovery ? new byte[0] : engineId;
            int b = discovery ? 0 : boots;
            int t = discovery ? 0 : CurTime();
            byte[] user = discovery ? new byte[0] : Encoding.UTF8.GetBytes(User ?? "");

            byte[] scoped = Ber.Tlv(0x30, Ber.Cat(Ber.Oct(eng), Ber.Oct(new byte[0]), pdu));
            byte[] privParams = new byte[0];
            byte[] msgData = scoped;
            if (priv) msgData = Ber.Oct(Encrypt(scoped, b, t, out privParams));

            int macLen = auth ? MacLen : 0;
            byte[] pEng = Ber.Oct(eng), pB = Ber.Int(b), pT = Ber.Int(t), pU = Ber.Oct(user);
            byte[] pA = Ber.Oct(new byte[macLen]), pP = Ber.Oct(privParams);
            byte[] secContent = Ber.Cat(pEng, pB, pT, pU, pA, pP);
            byte[] secSeq = Ber.Tlv(0x30, secContent);
            byte[] header = Ber.Tlv(0x30, Ber.Cat(Ber.Int(mid), Ber.Int(65507), Ber.Oct(new byte[] { flags }), Ber.Int(3)));
            byte[] ver = Ber.Int(3);
            byte[] content = Ber.Cat(ver, header, Ber.Oct(secSeq), msgData);
            byte[] msg = Ber.Tlv(0x30, content);

            if (auth)
            {
                int off = Ber.HdrLen(content.Length) + ver.Length + header.Length
                        + Ber.HdrLen(secSeq.Length) + Ber.HdrLen(secContent.Length)
                        + pEng.Length + pB.Length + pT.Length + pU.Length + Ber.HdrLen(macLen);
                byte[] mac = Hmac(msg);
                Buffer.BlockCopy(mac, 0, msg, off, macLen);
            }
            return msg;
        }

        static bool MatchV3(byte[] raw, int mid)
        {
            try
            {
                List<Node> c = Ber.Children(Ber.Read(raw).Data);
                return (int)Ber.ToInt(Ber.Children(c[1].Data)[0].Data) == mid;
            }
            catch { return false; }
        }

        PduResult ParseV3(byte[] raw)
        {
            List<Node> c = Ber.Children(Ber.Read(raw).Data);
            List<Node> sp = Ber.Children(Ber.Read(c[2].Data).Data);
            lastEngine = sp[0].Data;
            lastBoots = (int)Ber.ToInt(sp[1].Data);
            lastTime = (int)Ber.ToInt(sp[2].Data);
            byte[] rPriv = sp[5].Data;

            Node scoped = c[3];
            List<Node> sc;
            if (scoped.Tag == 0x04)
            {
                try
                {
                    byte[] plain = Decrypt(scoped.Data, lastBoots, lastTime, rPriv);
                    sc = Ber.Children(Ber.Read(plain).Data);
                }
                catch (Exception)
                {
                    throw new Exception("Antwort konnte nicht entschluesselt werden - Privacy-Passwort / -Protokoll pruefen");
                }
            }
            else sc = Ber.Children(scoped.Data);
            return ParsePdu(sc[2]);
        }

        void HandleReport(PduResult r)
        {
            string oid = r.VarBinds.Count > 0 ? r.VarBinds[0].Oid : "";
            const string usm = ".1.3.6.1.6.3.15.1.1.";
            if (oid.StartsWith(usm + "2."))
            {
                boots = lastBoots; timeBase = lastTime; timeSync = DateTime.UtcNow; return;
            }
            if (oid.StartsWith(usm + "4."))
            {
                engineId = lastEngine; boots = lastBoots; timeBase = lastTime; timeSync = DateTime.UtcNow;
                DeriveKeys(); return;
            }
            if (oid.StartsWith(usm + "1.")) throw new Exception("SNMPv3: Sicherheitsstufe vom Agent nicht unterstuetzt (Sicherheitsstufe pruefen)");
            if (oid.StartsWith(usm + "3.")) throw new Exception("SNMPv3: Unbekannter Benutzername");
            if (oid.StartsWith(usm + "5.")) throw new Exception("SNMPv3: Falsches Auth-Passwort oder Auth-Protokoll");
            if (oid.StartsWith(usm + "6.")) throw new Exception("SNMPv3: Entschluesselung fehlgeschlagen - Privacy-Passwort / -Protokoll pruefen");
            throw new Exception("SNMPv3-Report vom Agent: " + oid);
        }

        // ---------------------------------------------------------------- Verschluesselung
        static byte[] BE32(uint v) { return new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }; }

        static byte[] Sub(byte[] a, int off, int len) { byte[] r = new byte[len]; Buffer.BlockCopy(a, off, r, 0, len); return r; }

        byte[] Encrypt(byte[] plain, int b, int t, out byte[] privParams)
        {
            if (PrivProto == "DES")
            {
                desSalt++;
                byte[] salt = Ber.Cat(BE32((uint)b), BE32(desSalt));
                privParams = salt;
                byte[] iv = DesIv(salt);
                int pad = (8 - plain.Length % 8) % 8;
                byte[] data = new byte[plain.Length + pad];
                Buffer.BlockCopy(plain, 0, data, 0, plain.Length);
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC; des.Padding = PaddingMode.None;
                    using (ICryptoTransform tr = des.CreateEncryptor(Sub(privKey, 0, 8), iv))
                        return tr.TransformFinalBlock(data, 0, data.Length);
                }
            }
            aesSalt++;
            byte[] s8 = Ber.Cat(BE32((uint)(aesSalt >> 32)), BE32((uint)aesSalt));
            privParams = s8;
            return AesCfb(Sub(privKey, 0, 16), Ber.Cat(BE32((uint)b), BE32((uint)t), s8), plain, true);
        }

        byte[] Decrypt(byte[] cipher, int b, int t, byte[] salt)
        {
            if (PrivProto == "DES")
            {
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC; des.Padding = PaddingMode.None;
                    int len = cipher.Length - cipher.Length % 8;
                    using (ICryptoTransform tr = des.CreateDecryptor(Sub(privKey, 0, 8), DesIv(salt)))
                        return tr.TransformFinalBlock(cipher, 0, len);
                }
            }
            return AesCfb(Sub(privKey, 0, 16), Ber.Cat(BE32((uint)b), BE32((uint)t), salt), cipher, false);
        }

        byte[] DesIv(byte[] salt)
        {
            byte[] iv = new byte[8];
            for (int i = 0; i < 8; i++) iv[i] = (byte)(privKey[8 + i] ^ salt[i]);
            return iv;
        }

        static byte[] AesCfb(byte[] key, byte[] iv, byte[] input, bool encrypt)
        {
            byte[] output = new byte[input.Length];
            using (RijndaelManaged aes = new RijndaelManaged())
            {
                aes.BlockSize = 128; aes.KeySize = 128;
                aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
                aes.Key = key; aes.IV = new byte[16];
                using (ICryptoTransform enc = aes.CreateEncryptor())
                {
                    byte[] fb = (byte[])iv.Clone();
                    byte[] ks = new byte[16];
                    for (int i = 0; i < input.Length; i += 16)
                    {
                        enc.TransformBlock(fb, 0, 16, ks, 0);
                        int n = Math.Min(16, input.Length - i);
                        byte[] nf = new byte[16];
                        for (int j = 0; j < n; j++)
                        {
                            output[i + j] = (byte)(input[i + j] ^ ks[j]);
                            nf[j] = encrypt ? output[i + j] : input[i + j];
                        }
                        fb = nf;
                    }
                }
            }
            return output;
        }
    }

    // Walk im Hintergrund-Thread, damit die Oberflaeche bedienbar bleibt
    public class WalkJob
    {
        public volatile bool Done;
        public volatile int Count;
        public volatile string Phase = "Start";
        public List<VarBind> Result;
        public Exception Error;

        public static WalkJob Start(SnmpClient c, string root)
        {
            WalkJob j = new WalkJob();
            Thread t = new Thread(delegate ()
            {
                try
                {
                    j.Phase = "Verbinde";
                    c.Open();
                    c.Get(".1.3.6.1.2.1.1.1.0");
                    j.Phase = "Walk";
                    j.Result = c.Walk(root, delegate (int n) { j.Count = n; });
                }
                catch (Exception ex) { j.Error = ex; }
                finally
                {
                    try { c.Dispose(); } catch { }
                    j.Done = true;
                }
            });
            t.IsBackground = true;
            t.Start();
            return j;
        }
    }
}
'@

# =============================================================================
#  Auswertungsregeln (HPE CPQ-MIBs, Enterprise 232)
# =============================================================================
$script:HpeBase = '.1.3.6.1.4.1.232'

function New-EnumMap([string]$Spec) {
    $h = @{}
    foreach ($p in $Spec.Split(',')) {
        $x = $p.Split(':')
        $sev = ''
        if ($x.Count -gt 2) { $sev = $x[2] }
        $h[$x[0]] = [pscustomobject]@{ Name = $x[1]; Sev = $sev }
    }
    return $h
}

$Maps = @{
    COND  = New-EnumMap '1:other:I,2:ok:O,3:degraded:W,4:failed:C'
    CPU   = New-EnumMap '1:unknown:I,2:ok:O,3:degraded:W,4:failed:C,5:disabled:W'
    RED   = New-EnumMap '1:other:I,2:notRedundant:W,3:redundant:O'
    BATT  = New-EnumMap '1:other:I,2:ok:O,3:recharging:W,4:failed:C,5:degraded:W,6:notPresent:I,7:capacitorFailed:C'
    SMART = New-EnumMap '1:other:I,2:ok:O,3:replaceDrive:C,4:replaceDriveSSDWearOut:W'
    PHY   = New-EnumMap '1:other:I,2:ok:O,3:failed:C,4:predictiveFailure:W,5:erasing:W,6:eraseDone:W,7:eraseQueued:W,8:ssdWearOut:W,9:notAuthenticated:W'
    LOGD  = New-EnumMap '1:other:I,2:ok:O,3:failed:C,4:unconfigured:W,5:recovering:W,6:readyForRebuild:W,7:rebuilding:W,8:wrongDrive:C,9:badConnect:C,10:overheating:C,11:shutdown:C,12:expanding:W,13:notAvailable:C,14:queuedForExpansion:W,15:multipathAccessDegraded:W,16:erasing:W,17:predictiveSpareRebuildReady:W'
    PSUST = New-EnumMap '1:noError:O,2:generalFailure:C,3:bistFailure:C,4:fanFailure:C,5:tempFailure:C,6:interlockOpen:C,7:epromFailed:C,8:vrefFailed:C,9:dacFailed:C,10:ramTestFailed:C,11:voltageChannelFailed:C,12:orringdiodeFailed:C,13:brownOut:C,14:giveupOnStartup:C,15:nvramInvalid:C,16:calibrationTableInvalid:C,17:noPowerInput:C'
    LOC   = New-EnumMap '1:other,2:unknown,3:system,4:systemBoard,5:ioBoard,6:cpu,7:memory,8:storage,9:removableMedia,10:powerSupply,11:ambient,12:chassis,13:bridgeCard'
}

# K = S (Skalar) / T (Tabellenspalte), P = OID relativ zu 232, M = Enum, C = Kontext, A = Empfehlung
$Rules = @(
    @{ K = 'S'; P = '.6.2.6.1.0';      L = 'Thermik gesamt';             M = 'COND';  C = '';     A = 'Kühlung, Lüfter und Umgebungstemperatur prüfen' }
    @{ K = 'S'; P = '.6.2.6.3.0';      L = 'Temperaturstatus';           M = 'COND';  C = '';     A = 'Temperatursensoren im iLO prüfen' }
    @{ K = 'S'; P = '.6.2.6.4.0';      L = 'Systemlüfter-Status';        M = 'COND';  C = '';     A = 'Systemlüfter prüfen / tauschen' }
    @{ K = 'S'; P = '.6.2.6.5.0';      L = 'CPU-Lüfter-Status';          M = 'COND';  C = '';     A = 'CPU-Lüfter prüfen / tauschen' }
    @{ K = 'T'; P = '.6.2.6.8.1.6';    L = 'Temperatursensor';           M = 'COND';  C = 'TEMP'; A = 'Kühlung / Luftstrom / Raumtemperatur prüfen' }
    @{ K = 'T'; P = '.6.2.6.7.1.9';    L = 'Lüfter';                     M = 'COND';  C = 'FAN';  A = 'Lüfter prüfen / tauschen' }
    @{ K = 'S'; P = '.6.2.9.1.0';      L = 'Netzteile gesamt';           M = 'COND';  C = '';     A = 'Netzteile und Stromzufuhr prüfen' }
    @{ K = 'T'; P = '.6.2.9.3.1.4';    L = 'Netzteil';                   M = 'COND';  C = 'PSU';  A = 'Netzteil / Stromzufuhr prüfen, ggf. tauschen' }
    @{ K = 'T'; P = '.6.2.9.3.1.5';    L = 'Netzteil-Status';            M = 'PSUST'; C = 'PSU';  A = 'Netzteil / Stromzufuhr prüfen, ggf. tauschen' }
    @{ K = 'T'; P = '.6.2.9.3.1.9';    L = 'Netzteil-Redundanz';         M = 'RED';   C = 'PSU';  A = 'Zweites Netzteil vorhanden und angeschlossen?' }
    @{ K = 'S'; P = '.6.2.14.4.0';     L = 'Arbeitsspeicher gesamt';     M = 'COND';  C = '';     A = 'Speichermodule im iLO prüfen' }
    @{ K = 'T'; P = '.6.2.14.13.1.20'; L = 'Speichermodul';              M = 'COND';  C = 'MEM';  A = 'DIMM prüfen / tauschen' }
    @{ K = 'S'; P = '.6.2.11.2.0';     L = 'IML (Integrated Mgmt Log)';  M = 'COND';  C = '';     A = 'IML im iLO prüfen, nach Behebung als repariert markieren' }
    @{ K = 'T'; P = '.1.2.2.1.1.6';    L = 'Prozessor';                  M = 'CPU';   C = 'CPU';  A = 'CPU-Status im iLO prüfen' }
    @{ K = 'T'; P = '.3.2.2.1.1.6';    L = 'Array-Controller';           M = 'COND';  C = 'CTRL'; A = 'Controller und Firmware prüfen' }
    @{ K = 'T'; P = '.3.2.2.1.1.12';   L = 'Controller-Board';           M = 'COND';  C = 'CTRL'; A = 'Controller-Hardware prüfen' }
    @{ K = 'T'; P = '.3.2.2.2.1.9';    L = 'Controller-Cache';           M = 'COND';  C = 'ACC';  A = 'Cache-Modul prüfen' }
    @{ K = 'T'; P = '.3.2.2.2.1.6';    L = 'Cache-Batterie/Kondensator'; M = 'BATT';  C = 'ACC';  A = 'Smart-Storage-Batterie prüfen / tauschen' }
    @{ K = 'T'; P = '.3.2.3.1.1.4';    L = 'Logisches Laufwerk Status';  M = 'LOGD';  C = 'LOG';  A = 'Array-Status prüfen (Rebuild abwarten, defekte Disk tauschen)' }
    @{ K = 'T'; P = '.3.2.3.1.1.11';   L = 'Logisches Laufwerk';         M = 'COND';  C = 'LOG';  A = 'Array-Status prüfen' }
    @{ K = 'T'; P = '.3.2.5.1.1.6';    L = 'Physische Disk Status';      M = 'PHY';   C = 'PHY';  A = 'Disk tauschen' }
    @{ K = 'T'; P = '.3.2.5.1.1.37';   L = 'Physische Disk';             M = 'COND';  C = 'PHY';  A = 'Disk prüfen / tauschen' }
    @{ K = 'T'; P = '.3.2.5.1.1.57';   L = 'Disk S.M.A.R.T.';            M = 'SMART'; C = 'PHY';  A = 'Disk tauschen' }
)

$SubNames = @{
    '1' = 'Standard-Equipment (cpqSe)'; '2' = 'Systeminfo (cpqSi)'; '3' = 'Smart Array (cpqDa)'
    '5' = 'SCSI/SAS (cpqScsi)'; '6' = 'Health gesamt (cpqHe)'; '8' = 'Storage-Systeme (cpqSs)'
    '9' = 'iLO (cpqSm2)'; '11' = 'Host-OS (cpqHo)'; '14' = 'IDE/SATA (cpqIde)'
    '16' = 'Fibre Channel (cpqFca)'; '18' = 'Netzwerk/NIC (cpqNic)'; '22' = 'Rack (cpqRack)'
}

$De = @{
    ok = 'OK'; other = 'nicht zutreffend'; degraded = 'beeinträchtigt'; failed = 'ausgefallen'
    unknown = 'unbekannt'; disabled = 'deaktiviert'; notRedundant = 'nicht redundant'; redundant = 'redundant'
    recharging = 'wird geladen'; notPresent = 'nicht vorhanden'; capacitorFailed = 'Kondensator defekt'
    replaceDrive = 'Laufwerk tauschen'; replaceDriveSSDWearOut = 'SSD verschlissen'
    predictiveFailure = 'Ausfall vorhergesagt'; erasing = 'wird gelöscht'; eraseDone = 'gelöscht'
    eraseQueued = 'Löschung geplant'; ssdWearOut = 'SSD verschlissen'; notAuthenticated = 'nicht authentifiziert'
    unconfigured = 'nicht konfiguriert'; recovering = 'Wiederherstellung'; readyForRebuild = 'bereit für Rebuild'
    rebuilding = 'Rebuild läuft'; wrongDrive = 'falsches Laufwerk'; badConnect = 'Verbindungsfehler'
    overheating = 'Überhitzung'; shutdown = 'abgeschaltet'; expanding = 'wird erweitert'
    notAvailable = 'nicht verfügbar'; queuedForExpansion = 'Erweiterung geplant'
    multipathAccessDegraded = 'Multipath beeinträchtigt'; predictiveSpareRebuildReady = 'Spare-Rebuild bereit'
    noError = 'OK'; noPowerInput = 'keine Eingangsspannung'; generalFailure = 'allgemeiner Fehler'
    fanFailure = 'Lüfterfehler'; tempFailure = 'Temperaturfehler'; brownOut = 'Unterspannung'
    unbekannt = 'unbekannter Wert'
}

# =============================================================================
#  Auswertung
# =============================================================================
function Get-EnumName($map, $v) {
    $entry = $script:Maps[$map][[string]$v]
    if ($entry) { return $entry.Name }
    return [string]$v
}

function Get-Ctx($c, $idx) {
    $V = $script:Val
    switch ($c) {
        'TEMP' {
            $b = $script:HpeBase + '.6.2.6.8.1.'
            $s = "Sensor $idx"
            if ($V.ContainsKey($b + '3.' + $idx)) { $s += ' (' + (Get-EnumName 'LOC' $V[$b + '3.' + $idx]) + ')' }
            if ($V.ContainsKey($b + '4.' + $idx)) { $s += ', ' + $V[$b + '4.' + $idx] + ' °C' }
            if ($V.ContainsKey($b + '5.' + $idx) -and ($V[$b + '5.' + $idx] -as [int]) -gt 0) { $s += ' / Schwelle ' + $V[$b + '5.' + $idx] + ' °C' }
            return $s
        }
        'FAN' {
            $b = $script:HpeBase + '.6.2.6.7.1.'
            $s = "Lüfter $idx"
            if ($V.ContainsKey($b + '3.' + $idx)) { $s += ' (' + (Get-EnumName 'LOC' $V[$b + '3.' + $idx]) + ')' }
            return $s
        }
        'PHY' {
            $b = $script:HpeBase + '.3.2.5.1.1.'
            $s = "Disk $idx"
            if ($V[$b + '64.' + $idx]) { $s += ' [' + $V[$b + '64.' + $idx] + ']' }
            if ($V[$b + '3.' + $idx]) { $s += ' ' + $V[$b + '3.' + $idx] }
            return $s
        }
        'PSU'  { return "Netzteil $idx" }
        'LOG'  { return "Log. Laufwerk $idx" }
        'CTRL' { return "Controller $idx" }
        'ACC'  { return "Cache-Modul $idx" }
        'MEM'  { return "DIMM $idx" }
        'CPU'  { return "CPU $idx" }
    }
    return [string]$idx
}

function Add-Check($label, $map, $ctx, $oid, $idx, $action) {
    $v = [string]$script:Val[$oid]
    $entry = $script:Maps[$map][$v]
    if ($entry) { $sev = $entry.Sev; $name = $entry.Name } else { $sev = 'W'; $name = 'unbekannt' }
    switch ($sev) { 'O' { $st = 'OK' } 'I' { $st = 'NA' } 'C' { $st = 'CRIT' } default { $st = 'WARN' } }
    $inst = '-'
    if ($idx -ne '') { $inst = Get-Ctx $ctx $idx }
    $bed = $De[$name]
    if (-not $bed) { $bed = $name }
    $emp = ''
    if ($st -eq 'WARN' -or $st -eq 'CRIT') { $emp = $action }
    $script:Checks.Add([pscustomobject]@{
            Stufe = $st; Komponente = $label; Instanz = $inst; Wert = "$name($v)"
            Bedeutung = $bed; Empfehlung = $emp; OID = $oid
        })
}

function Invoke-Evaluation($Items) {
    $script:Val = @{}
    foreach ($it in $Items) { $script:Val[$it.Oid] = $it.Value }
    $script:Checks = New-Object System.Collections.Generic.List[object]
    $hpe = @($Items | Where-Object { $_.Oid.StartsWith($script:HpeBase + '.', [StringComparison]::Ordinal) } | ForEach-Object { $_.Oid })

    foreach ($r in $Rules) {
        $full = $script:HpeBase + $r.P
        if ($r.K -eq 'S') {
            if ($script:Val.ContainsKey($full)) { Add-Check $r.L $r.M $r.C $full '' $r.A }
            continue
        }
        $pfx = $full + '.'
        foreach ($o in $hpe) {
            if ($o.StartsWith($pfx, [StringComparison]::Ordinal)) { Add-Check $r.L $r.M $r.C $o $o.Substring($pfx.Length) $r.A }
        }
    }
    foreach ($o in $hpe) {
        if ($o -match '^\.1\.3\.6\.1\.4\.1\.232\.(\d+)\.1\.3\.0$') {
            $n = $Matches[1]
            $name = $SubNames[$n]
            if (-not $name) { $name = "Subsystem $n" }
            Add-Check "Subsystem $name" 'COND' '' $o '' 'Details im iLO prüfen'
        }
    }

    $V = $script:Val
    $S = '.1.3.6.1.2.1.1.'
    $info = [ordered]@{}
    if ($V[$S + '5.0'])        { $info['Hostname'] = $V[$S + '5.0'] }
    if ($V[$script:HpeBase + '.2.2.4.2.0']) { $info['Modell'] = $V[$script:HpeBase + '.2.2.4.2.0'] }
    if ($V[$script:HpeBase + '.2.2.2.1.0']) { $info['Seriennummer'] = $V[$script:HpeBase + '.2.2.2.1.0'] }
    if ($V[$script:HpeBase + '.1.2.6.1.0']) { $info['System-ROM'] = $V[$script:HpeBase + '.1.2.6.1.0'] }
    if ($V[$S + '1.0'])        { $info['Agent / iLO'] = $V[$S + '1.0'] }
    if ($V[$S + '3.0'] -match '^\d+$') {
        $ts = [TimeSpan]::FromSeconds([math]::Floor([double]$V[$S + '3.0'] / 100))
        $info['Uptime Agent'] = '{0} Tage {1:00}:{2:00} h' -f $ts.Days, $ts.Hours, $ts.Minutes
    }
    if ($V[$script:HpeBase + '.6.1.3.0']) {
        $hn = Get-EnumName 'COND' $V[$script:HpeBase + '.6.1.3.0']
        $hd = $De[$hn]; if (-not $hd) { $hd = $hn }
        $info['Health gesamt'] = $hd
    }
    $info['OIDs im Walk'] = '{0} (davon HPE: {1})' -f $Items.Count, $hpe.Count

    $crit = @($script:Checks | Where-Object Stufe -eq 'CRIT')
    $warn = @($script:Checks | Where-Object Stufe -eq 'WARN')
    $code = 0
    if ($hpe.Count -eq 0) { $code = 3 } elseif ($crit.Count) { $code = 2 } elseif ($warn.Count) { $code = 1 }

    [pscustomobject]@{
        Info     = $info
        Checks   = $script:Checks
        Findings = @($crit + $warn)
        Ok       = @($script:Checks | Where-Object Stufe -eq 'OK').Count
        Na       = @($script:Checks | Where-Object Stufe -eq 'NA').Count
        Warn     = $warn.Count
        Crit     = $crit.Count
        HpeCount = $hpe.Count
        Code     = $code
    }
}

function Get-StatusText($code) {
    switch ($code) { 0 { 'OK' } 1 { 'WARNUNG' } 2 { 'KRITISCH' } default { 'UNBEKANNT' } }
}

# =============================================================================
#  Berichte
# =============================================================================
function Write-TextReport($Path, $Name, $Ev, $Meta) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('HPE ProLiant SNMP-Healthcheck')
    [void]$sb.AppendLine(('=' * 78))
    foreach ($k in $Meta.Keys) { [void]$sb.AppendLine(('{0,-14}: {1}' -f $k, $Meta[$k])) }
    foreach ($k in $Ev.Info.Keys) { [void]$sb.AppendLine(('{0,-14}: {1}' -f $k, $Ev.Info[$k])) }
    [void]$sb.AppendLine(('{0,-14}: {1}' -f 'Gesamtstatus', (Get-StatusText $Ev.Code)))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('Geprüft: {0} | OK: {1} | Warnung: {2} | Kritisch: {3} | n.a.: {4}' -f $Ev.Checks.Count, $Ev.Ok, $Ev.Warn, $Ev.Crit, $Ev.Na))
    [void]$sb.AppendLine('')
    if ($Ev.Findings.Count) {
        [void]$sb.AppendLine('WERTE MIT FEHLER / WARNUNG')
        [void]$sb.AppendLine(('-' * 78))
        foreach ($f in $Ev.Findings) {
            [void]$sb.AppendLine(('{0,-5} {1,-30} {2}' -f $f.Stufe, $f.Komponente, $f.Instanz))
            [void]$sb.AppendLine(('      Wert: {0} ({1})' -f $f.Wert, $f.Bedeutung))
            [void]$sb.AppendLine(('      Empfehlung: {0}' -f $f.Empfehlung))
            [void]$sb.AppendLine(('      OID: {0}' -f $f.OID))
        }
    } else { [void]$sb.AppendLine('Keine Warnungen oder Fehler gefunden.') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('ALLE GEPRÜFTEN WERTE')
    [void]$sb.AppendLine(('-' * 78))
    foreach ($c in $Ev.Checks) {
        [void]$sb.AppendLine(('{0,-5} {1,-30} {2,-40} {3}' -f $c.Stufe, $c.Komponente, $c.Instanz, $c.Wert))
    }
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($true)))
}

function H($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Write-HtmlReport($Path, $Name, $Ev, $Meta) {
    $statusTxt = Get-StatusText $Ev.Code
    $statusCls = @('ok', 'warn', 'crit', 'unk')[[math]::Min($Ev.Code, 3)]
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HPE Healthcheck – $(H $Name)</title>
<style>
:root{--navy:#0A1628;--navy2:#12223F;--green:#2BE38F;--cyan:#22D3EE;--blue:#2F8BFF;--deep:#1659E6;
--grad:linear-gradient(90deg,#2BE38F,#22D3EE 45%,#2F8BFF);--text:#3A4A63;--light:#F4F7FB;--line:#DEE5EF;
--ok:#1E9E62;--warn:#E0A800;--crit:#D93848;--na:#8A96A8}
*{box-sizing:border-box}
body{margin:0;background:var(--light);color:var(--text);font-family:'Segoe UI','IBM Plex Sans',Arial,sans-serif;font-size:15px;line-height:1.45}
header{background:var(--navy);color:#fff;padding:22px 32px 20px;position:relative}
header:after{content:"";position:absolute;left:0;right:0;bottom:0;height:4px;background:var(--grad)}
.brand{display:flex;align-items:center;gap:10px;font-size:14px;color:#93A6C2;letter-spacing:.02em}
.brand .mark{font-family:Montserrat,'Segoe UI',sans-serif;font-weight:800;font-style:italic;font-size:20px;background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
h1{font-family:Montserrat,'Segoe UI',sans-serif;font-weight:800;margin:12px 0 2px;font-size:27px;color:#fff}
.sub{color:#C9D6EA}
main{max-width:1180px;margin:0 auto;padding:24px 32px 40px}
h2{font-family:Montserrat,'Segoe UI',sans-serif;color:var(--navy);font-size:20px;margin:30px 0 12px;display:flex;align-items:center;gap:10px}
h2:before{content:"";width:18px;height:4px;border-radius:2px;background:var(--grad);display:inline-block}
.card{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(10,22,40,.08);padding:18px 22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}
.tile{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(10,22,40,.08);padding:16px 18px;border-top:4px solid var(--line)}
.tile .n{font-size:32px;font-weight:700;color:var(--navy)}
.tile.ok{border-top-color:var(--ok)}.tile.warn{border-top-color:var(--warn)}.tile.crit{border-top-color:var(--crit)}.tile.na{border-top-color:var(--na)}
.status{display:inline-block;padding:6px 16px;border-radius:20px;font-weight:700;font-size:16px}
.status.ok{background:#E3F7EC;color:var(--ok)}.status.warn{background:#FFF4CC;color:#8A6500}
.status.crit{background:#FDE7EA;color:var(--crit)}.status.unk{background:#E9EDF3;color:#556}
table{width:100%;border-collapse:collapse;background:#fff}
th{background:var(--navy);color:#fff;text-align:left;padding:9px 10px;font-weight:600;font-size:14px}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
tr:nth-child(even) td{background:#F9FBFD}
.kv td:first-child{width:180px;font-weight:600;color:var(--navy)}
.b{display:inline-block;min-width:74px;text-align:center;padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px}
.b.CRIT{background:var(--crit);color:#fff}.b.WARN{background:var(--warn);color:var(--navy)}
.b.OK{background:var(--ok);color:#fff}.b.NA{background:#DDE3EC;color:#556}
.oid{font-family:Consolas,'JetBrains Mono',monospace;font-size:12px;color:#7A889C;word-break:break-all}
details summary{cursor:pointer;font-weight:600;color:var(--navy);padding:6px 0}
.okbox{padding:16px 20px;background:#E3F7EC;color:var(--ok);border-radius:10px;font-weight:600}
footer{color:#999;font-size:12px;text-align:center;padding:20px}
@media (max-width:700px){main,header{padding-left:16px;padding-right:16px}.hide-m{display:none}}
@media print{body{background:#fff}.card,.tile{box-shadow:none;border:1px solid var(--line)}}
</style></head><body>
<header>
  <div class="brand"><span class="mark">#Powerscripting</span><span>Elevate. Automate. Innovate.</span></div>
  <h1>HPE ProLiant Hardware-Healthcheck</h1>
  <div class="sub">$(H $Name)$(if ($Meta['Kunde']) { ' · ' + (H $Meta['Kunde']) }) · $(H $Meta['Erstellt'])</div>
</header>
<main>
<h2>Gesamtstatus</h2>
<div class="card"><span class="status $statusCls">$statusTxt</span></div>
<div class="grid" style="margin-top:14px">
  <div class="tile crit"><div>Kritisch</div><div class="n">$($Ev.Crit)</div></div>
  <div class="tile warn"><div>Warnung</div><div class="n">$($Ev.Warn)</div></div>
  <div class="tile ok"><div>OK</div><div class="n">$($Ev.Ok)</div></div>
  <div class="tile na"><div>nicht zutreffend</div><div class="n">$($Ev.Na)</div></div>
</div>
<h2>Systeminformationen</h2>
<div class="card" style="padding:0;overflow:hidden"><table class="kv">
"@)
    foreach ($k in $Meta.Keys) { if ($Meta[$k]) { [void]$sb.Append("<tr><td>$(H $k)</td><td>$(H $Meta[$k])</td></tr>") } }
    foreach ($k in $Ev.Info.Keys) { [void]$sb.Append("<tr><td>$(H $k)</td><td>$(H $Ev.Info[$k])</td></tr>") }
    [void]$sb.Append('</table></div>')

    [void]$sb.Append('<h2>Befunde – Fehler und Warnungen</h2>')
    if ($Ev.HpeCount -eq 0) {
        [void]$sb.Append('<div class="card">Es wurden keine HPE-Statuswerte gefunden. Bitte prüfen, ob im Betriebssystem der Agentless Management Service (AMS) bzw. die HPE Insight Agents installiert sind und SNMP im iLO aktiviert ist.</div>')
    } elseif ($Ev.Findings.Count -eq 0) {
        [void]$sb.Append('<div class="okbox">Keine Fehler oder Warnungen gefunden – alle geprüften Komponenten sind in Ordnung.</div>')
    } else {
        [void]$sb.Append('<div class="card" style="padding:0;overflow:auto"><table><tr><th>Stufe</th><th>Komponente</th><th>Instanz</th><th>Status</th><th>Empfehlung</th><th class="hide-m">OID</th></tr>')
        foreach ($f in $Ev.Findings) {
            $lbl = 'Warnung'; if ($f.Stufe -eq 'CRIT') { $lbl = 'Kritisch' }
            [void]$sb.Append("<tr><td><span class=""b $($f.Stufe)"">$lbl</span></td><td>$(H $f.Komponente)</td><td>$(H $f.Instanz)</td><td><b>$(H $f.Bedeutung)</b><br><span class=""oid"">$(H $f.Wert)</span></td><td>$(H $f.Empfehlung)</td><td class=""oid hide-m"">$(H $f.OID)</td></tr>")
        }
        [void]$sb.Append('</table></div>')
    }

    [void]$sb.Append("<h2>Alle geprüften Komponenten</h2><div class=""card""><details><summary>$($Ev.Checks.Count) Statuswerte anzeigen</summary><table><tr><th>Stufe</th><th>Komponente</th><th>Instanz</th><th>Status</th><th class=""hide-m"">OID</th></tr>")
    foreach ($c in $Ev.Checks) {
        $lbl = switch ($c.Stufe) { 'CRIT' { 'Kritisch' } 'WARN' { 'Warnung' } 'OK' { 'OK' } default { 'n.a.' } }
        [void]$sb.Append("<tr><td><span class=""b $($c.Stufe)"">$lbl</span></td><td>$(H $c.Komponente)</td><td>$(H $c.Instanz)</td><td>$(H $c.Bedeutung) <span class=""oid"">$(H $c.Wert)</span></td><td class=""oid hide-m"">$(H $c.OID)</td></tr>")
    }
    [void]$sb.Append("</table></details></div></main><footer>HPE ProLiant SNMP-Healthcheck v$ToolVersion · #Powerscripting · powerscripting.de · erstellt $(H $Meta['Erstellt'])</footer></body></html>")
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
}

# =============================================================================
#  Ablauf je Server (gemeinsam für GUI und Kommandozeile)
#    $Cfg  : Hashtable mit Verbindungsdaten
#    $Tick : Scriptblock, wird während des Walks zyklisch mit dem WalkJob aufgerufen
# =============================================================================
function Get-FriendlyError($Ex, $Phase) {
    if ($Ex -is [System.OperationCanceledException]) { return 'Vom Benutzer abgebrochen.' }
    if ($Ex -is [System.TimeoutException]) {
        if ($Phase -eq 'Walk') { return 'Der Agent antwortet während des Walks nicht mehr (Timeout). Timeout erhöhen oder Umfang "Nur HPE" wählen.' }
        return 'Keine Antwort vom iLO. Prüfen: IP/Hostname, Firewall (UDP 161), SNMP im iLO aktiviert, Community bzw. SNMPv3-Zugangsdaten.'
    }
    if ($Ex -is [System.Net.Sockets.SocketException]) { return "Netzwerkfehler: $($Ex.Message)" }
    return $Ex.Message
}

function Invoke-HealthCheck {
    param([string]$Name, [hashtable]$Cfg, [string]$File, [scriptblock]$Tick)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safe = $Name -replace '[^\w\.-]', '_'
    $meta = [ordered]@{}
    if ($Cfg.Customer) { $meta['Kunde'] = $Cfg.Customer }
    $meta['Ziel'] = $Name
    $meta['Erstellt'] = (Get-Date -Format 'dd.MM.yyyy HH:mm')
    $res = [pscustomobject]@{ Name = $Name; Ev = $null; Html = $null; Txt = $null; Walk = $null; Error = $null; Seconds = 0 }

    try {
        if (-not (Test-Path $Cfg.OutDir)) { New-Item -ItemType Directory -Path $Cfg.OutDir -Force | Out-Null }
        $items = New-Object System.Collections.Generic.List[object]

        if ($File) {
            foreach ($line in [IO.File]::ReadAllLines($File)) {
                if ($line -match '^(\.[0-9\.]+)\s?(.*)$') {
                    $val = $Matches[2]
                    if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Substring(1, $val.Length - 2).Replace('\"', '"') }
                    $items.Add([pscustomobject]@{ Oid = $Matches[1]; Value = $val })
                }
            }
            $safe = $safe -replace '^walk_', ''
            $meta['Quelle'] = 'Walk-Datei ' + [IO.Path]::GetFileName($File)
        } else {
            $c = New-Object PsSnmp.SnmpClient
            $c.Host = $Name; $c.Port = $Cfg.Port
            $c.TimeoutMs = $Cfg.TimeoutSec * 1000; $c.Retries = $Cfg.Retries; $c.MaxRepetitions = $Cfg.MaxRepetitions
            switch ($Cfg.Version) { '1' { $c.Version = 0 } '2c' { $c.Version = 1 } '3' { $c.Version = 3 } }
            $c.Community = $Cfg.Community
            $c.User = $Cfg.User; $c.Level = $Cfg.SecLevel
            $c.AuthProto = $Cfg.AuthProtocol; $c.AuthPass = $Cfg.AuthPassword
            $c.PrivProto = $Cfg.PrivProtocol; $c.PrivPass = $Cfg.PrivPassword
            $meta['SNMP'] = 'v' + $Cfg.Version
            $script:CurrentClient = $c

            $sw = [Diagnostics.Stopwatch]::StartNew()
            $job = [PsSnmp.WalkJob]::Start($c, $Cfg.Root)
            while (-not $job.Done) {
                if ($Tick) { & $Tick $job }
                Start-Sleep -Milliseconds 80
            }
            $sw.Stop()
            $script:CurrentClient = $null
            $res.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            if ($job.Error) { throw (Get-FriendlyError $job.Error $job.Phase) }

            $walkFile = Join-Path $Cfg.OutDir "walk_${safe}_$stamp.txt"
            $w = New-Object IO.StreamWriter($walkFile, $false, (New-Object Text.UTF8Encoding($false)))
            try {
                foreach ($vb in $job.Result) {
                    if ($vb.IsText) { $w.WriteLine($vb.Oid + ' "' + $vb.Value.Replace('"', '\"') + '"') }
                    else { $w.WriteLine($vb.Oid + ' ' + $vb.Value) }
                    $items.Add([pscustomobject]@{ Oid = $vb.Oid; Value = $vb.Value })
                }
            } finally { $w.Close() }
            $res.Walk = $walkFile
        }

        $ev = Invoke-Evaluation $items
        $res.Ev = $ev
        $res.Txt = Join-Path $Cfg.OutDir "report_${safe}_$stamp.txt"
        $res.Html = Join-Path $Cfg.OutDir "report_${safe}_$stamp.html"
        Write-TextReport $res.Txt $Name $ev $meta
        Write-HtmlReport $res.Html $Name $ev $meta
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception -is [System.Management.Automation.MethodInvocationException] -and $_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        $res.Error = $msg
    }
    return $res
}

function Initialize-Engine {
    if (-not ('PsSnmp.SnmpClient' -as [type])) {
        Add-Type -TypeDefinition $CSharp -Language CSharp -IgnoreWarnings -ErrorAction Stop
    }
}

function Get-DefaultOutDir {
    $d = Join-Path $PSScriptRoot 'Reports'
    try {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $probe = Join-Path $d ('.probe_' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, 'x'); Remove-Item $probe -Force
        return $d
    } catch {
        return (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'HPE-SNMP-Reports')
    }
}

# =============================================================================
#  GUI
# =============================================================================
function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    try { [void][PsSnmp.Native]::SetProcessDPIAware() } catch { }
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $cNavy = [Drawing.Color]::FromArgb(10, 22, 40)
    $cGreen = [Drawing.Color]::FromArgb(43, 227, 143)
    $cBlue = [Drawing.Color]::FromArgb(47, 139, 255)
    $cLight = [Drawing.Color]::FromArgb(244, 247, 251)
    $cRowCrit = [Drawing.Color]::FromArgb(253, 228, 225)
    $cRowWarn = [Drawing.Color]::FromArgb(255, 247, 190)
    $cRowOk = [Drawing.Color]::FromArgb(232, 245, 233)
    $fUi = New-Object Drawing.Font('Segoe UI', 9)
    $fBold = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)

    # DPI-Faktor ermitteln – alle festen Maße werden damit skaliert
    $gr = [Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
    $script:Scale = [math]::Max(1.0, $gr.DpiX / 96.0)
    $gr.Dispose()
    function Sc([double]$v) { [int][math]::Round($v * $script:Scale) }
    function Pad($l, $t, $r, $b) { New-Object Windows.Forms.Padding($l, $t, $r, $b) }
    function Sz($w, $h) { New-Object Drawing.Size($w, $h) }

    function New-Lbl([string]$Text, [switch]$Flow) {
        $l = New-Object Windows.Forms.Label
        $l.Text = $Text; $l.AutoSize = $true; $l.Anchor = 'Left'
        if ($Flow) { $l.Margin = Pad (Sc 10) (Sc 7) (Sc 4) 0 } else { $l.Margin = Pad 3 3 (Sc 10) 3 }
        return $l
    }
    function New-Txt([int]$W, [string]$Text) {
        $t = New-Object Windows.Forms.TextBox
        $t.Width = Sc $W; $t.Margin = Pad 3 (Sc 3) 3 (Sc 3)
        if ($Text) { $t.Text = $Text }
        return $t
    }
    function New-Combo([int]$W, [string[]]$Items, [string]$Sel) {
        $c = New-Object Windows.Forms.ComboBox
        $c.DropDownStyle = 'DropDownList'; $c.Width = Sc $W; $c.Margin = Pad 3 (Sc 3) 3 (Sc 3)
        [void]$c.Items.AddRange([object[]]$Items)
        $c.SelectedItem = $Sel
        return $c
    }
    function New-Btn([string]$Text, [int]$W) {
        $b = New-Object Windows.Forms.Button
        $b.Text = $Text; $b.AutoSize = $true; $b.AutoSizeMode = 'GrowOnly'
        $b.MinimumSize = Sz (Sc $W) (Sc 32); $b.Padding = Pad (Sc 6) 0 (Sc 6) 0; $b.Margin = Pad 3 3 (Sc 6) 3
        return $b
    }
    function New-Grid([object[]]$Cols) {
        $t = New-Object Windows.Forms.TableLayoutPanel
        $t.ColumnCount = $Cols.Count; $t.RowCount = 0
        foreach ($c in $Cols) {
            if ("$c" -eq 'A') { [void]$t.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::AutoSize))) }
            else { [void]$t.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, [single]$c))) }
        }
        $t.AutoSize = $true; $t.AutoSizeMode = 'GrowAndShrink'; $t.Dock = 'Fill'; $t.Margin = Pad 0 0 0 0
        return $t
    }
    function New-Flow {
        $f = New-Object Windows.Forms.FlowLayoutPanel
        $f.AutoSize = $true; $f.AutoSizeMode = 'GrowAndShrink'; $f.WrapContents = $false; $f.Margin = Pad 0 0 0 0
        return $f
    }
    function Add-Row($Grid, [object[]]$Ctls) {
        $r = $Grid.RowCount
        $Grid.RowCount = $r + 1
        [void]$Grid.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
        for ($i = 0; $i -lt $Ctls.Count; $i++) { $Grid.Controls.Add($Ctls[$i], $i, $r) }
    }
    function New-Group([string]$Text) {
        $g = New-Object Windows.Forms.GroupBox
        $g.Text = $Text; $g.Dock = 'Fill'; $g.AutoSize = $true; $g.AutoSizeMode = 'GrowAndShrink'
        $g.Padding = Pad (Sc 10) (Sc 8) (Sc 10) (Sc 8); $g.Margin = Pad (Sc 4) 0 (Sc 4) 0
        return $g
    }

    # ---------------------------------------------------------------- Formular
    $form = New-Object Windows.Forms.Form
    $form.Text = 'HPE ProLiant SNMP-Healthcheck – #Powerscripting'
    $form.AutoScaleMode = 'None'
    $form.Font = $fUi
    $form.ClientSize = Sz (Sc 1120) (Sc 800)
    $form.MinimumSize = Sz (Sc 1000) (Sc 700)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $cLight
    try { $form.Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Process -Id $PID).Path) } catch { }

    $root = New-Grid @(100)
    $root.AutoSize = $false; $root.Dock = 'Fill'
    $form.Controls.Add($root)

    # Kopfzeile
    $hdr = New-Flow
    $hdr.FlowDirection = 'TopDown'; $hdr.Dock = 'Fill'; $hdr.BackColor = $cNavy
    $hdr.Padding = Pad (Sc 18) (Sc 10) (Sc 18) (Sc 10)
    $lt = New-Object Windows.Forms.Label
    $lt.AutoSize = $true; $lt.Text = 'HPE ProLiant SNMP-Healthcheck'; $lt.Margin = Pad 0 0 0 0
    $lt.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold); $lt.ForeColor = [Drawing.Color]::White
    $ls = New-Object Windows.Forms.Label
    $ls.AutoSize = $true; $ls.Margin = Pad (Sc 2) (Sc 4) 0 0
    $ls.Text = "#Powerscripting   ·   Hardware-Status über das iLO auslesen   ·   v$ToolVersion"
    $ls.ForeColor = [Drawing.Color]::FromArgb(147, 166, 194)
    $hdr.Controls.AddRange(@($lt, $ls))
    Add-Row $root @($hdr)
    $strip = New-Object Windows.Forms.Panel
    $strip.Height = Sc 4; $strip.Anchor = 'Left, Right'; $strip.BackColor = $cBlue; $strip.Margin = Pad 0 0 0 0
    $strip.Add_Paint({
            param($sender, $e)
            if ($sender.Width -lt 2) { return }
            $r = $sender.ClientRectangle
            $br = New-Object Drawing.Drawing2D.LinearGradientBrush($r, $cGreen, $cBlue, [single]0)
            $e.Graphics.FillRectangle($br, $r); $br.Dispose()
        })
    $strip.Add_Resize({ $this.Invalidate() })
    Add-Row $root @($strip)

    # Einstellungen: zwei Gruppen nebeneinander
    $set = New-Grid @(52, 48)
    $set.Margin = Pad (Sc 8) (Sc 10) (Sc 8) 0
    Add-Row $root @($set)

    $gb1 = New-Group 'Verbindung'
    $g1 = New-Grid @('A', 100); $gb1.Controls.Add($g1)
    $tbHost = New-Txt 280; $tbHost.Anchor = 'Left, Right'
    Add-Row $g1 @((New-Lbl 'iLO-IP / Host(s):'), $tbHost)
    $tbCust = New-Txt 280; $tbCust.Anchor = 'Left, Right'
    Add-Row $g1 @((New-Lbl 'Kunde (für Bericht):'), $tbCust)
    $cbVer = New-Combo 70 @('1', '2c', '3') '2c'
    $cbRoot = New-Combo 230 @('Komplett (.1.3.6.1)', 'Nur HPE (.1.3.6.1.4.1.232)') 'Komplett (.1.3.6.1)'
    $f = New-Flow; $f.Controls.AddRange(@($cbVer, (New-Lbl 'Umfang:' -Flow), $cbRoot))
    Add-Row $g1 @((New-Lbl 'SNMP-Version:'), $f)
    $tbComm = New-Txt 200 'public'; $tbComm.UseSystemPasswordChar = $true
    $chkShow = New-Object Windows.Forms.CheckBox
    $chkShow.Text = 'anzeigen'; $chkShow.AutoSize = $true; $chkShow.Margin = Pad (Sc 10) (Sc 6) 0 0
    $f = New-Flow; $f.Controls.AddRange(@($tbComm, $chkShow))
    Add-Row $g1 @((New-Lbl 'Community:'), $f)
    $nuPort = New-Object Windows.Forms.NumericUpDown
    $nuPort.Minimum = 1; $nuPort.Maximum = 65535; $nuPort.Value = 161; $nuPort.Width = Sc 80; $nuPort.Margin = Pad 3 (Sc 3) 3 (Sc 3)
    $nuTo = New-Object Windows.Forms.NumericUpDown
    $nuTo.Minimum = 1; $nuTo.Maximum = 60; $nuTo.Value = 3; $nuTo.Width = Sc 60; $nuTo.Margin = Pad 3 (Sc 3) 3 (Sc 3)
    $f = New-Flow; $f.Controls.AddRange(@($nuPort, (New-Lbl 'Timeout (s):' -Flow), $nuTo))
    Add-Row $g1 @((New-Lbl 'Port:'), $f)

    $gb2 = New-Group 'SNMPv3 (nur bei Version 3)'
    $g2 = New-Grid @('A', 100); $gb2.Controls.Add($g2)
    $tbUser = New-Txt 220
    Add-Row $g2 @((New-Lbl 'Benutzer:'), $tbUser)
    $cbLvl = New-Combo 160 @('authPriv', 'authNoPriv', 'noAuthNoPriv') 'authPriv'
    Add-Row $g2 @((New-Lbl 'Sicherheitsstufe:'), $cbLvl)
    $cbAuth = New-Combo 95 @('SHA', 'SHA256', 'MD5') 'SHA'
    $tbAuth = New-Txt 190; $tbAuth.UseSystemPasswordChar = $true
    $f = New-Flow; $f.Controls.AddRange(@($cbAuth, (New-Lbl 'Passwort:' -Flow), $tbAuth))
    Add-Row $g2 @((New-Lbl 'Auth-Protokoll:'), $f)
    $cbPriv = New-Combo 95 @('AES', 'DES') 'AES'
    $tbPriv = New-Txt 190; $tbPriv.UseSystemPasswordChar = $true
    $f = New-Flow; $f.Controls.AddRange(@($cbPriv, (New-Lbl 'Passwort:' -Flow), $tbPriv))
    Add-Row $g2 @((New-Lbl 'Privacy-Protokoll:'), $f)
    $lHint = New-Lbl 'Gen10 und neuer: AMS im Betriebssystem erforderlich.'
    $lHint.ForeColor = [Drawing.Color]::Gray
    Add-Row $g2 @($lHint)
    $g2.SetColumnSpan($lHint, 2)

    Add-Row $set @($gb1, $gb2)

    # Ausgabeordner
    $og = New-Grid @('A', 100, 'A')
    $og.Margin = Pad (Sc 12) (Sc 8) (Sc 12) 0
    $tbOut = New-Txt 300 (Get-DefaultOutDir); $tbOut.Anchor = 'Left, Right'
    $btnOut = New-Btn '…' 40
    Add-Row $og @((New-Lbl 'Ausgabeordner:'), $tbOut, $btnOut)
    Add-Row $root @($og)

    # Buttons
    $bg = New-Grid @(100, 'A')
    $bg.Margin = Pad (Sc 10) (Sc 6) (Sc 10) 0
    $btnStart = New-Btn 'Walk starten' 150
    $btnStart.BackColor = $cBlue; $btnStart.ForeColor = [Drawing.Color]::White; $btnStart.Font = $fBold
    $btnStart.FlatStyle = 'Flat'; $btnStart.FlatAppearance.BorderColor = $cNavy
    $btnCancel = New-Btn 'Abbrechen' 110; $btnCancel.Enabled = $false
    $btnFile = New-Btn 'Walk-Datei auswerten …' 170
    $fl = New-Flow; $fl.Controls.AddRange(@($btnStart, $btnCancel, $btnFile))
    $btnReport = New-Btn 'Bericht öffnen' 120; $btnReport.Enabled = $false
    $btnFolder = New-Btn 'Ordner öffnen' 110
    $fr = New-Flow; $fr.Controls.AddRange(@($btnReport, $btnFolder))
    Add-Row $bg @($fl, $fr)
    Add-Row $root @($bg)

    # Fortschritt
    $pg = New-Grid @('A', 100)
    $pg.Margin = Pad (Sc 12) (Sc 8) (Sc 12) (Sc 2)
    $prg = New-Object Windows.Forms.ProgressBar
    $prg.Size = Sz (Sc 360) (Sc 18); $prg.Anchor = 'Left'; $prg.Margin = Pad 3 3 (Sc 12) 3
    $lblStat = New-Lbl 'Bereit.'
    Add-Row $pg @($prg, $lblStat)
    Add-Row $root @($pg)

    # Ergebnisse
    $tabs = New-Object Windows.Forms.TabControl
    $tabs.Dock = 'Fill'; $tabs.Margin = Pad (Sc 12) (Sc 6) (Sc 12) (Sc 12)
    $rr = $root.RowCount; $root.RowCount = $rr + 1
    [void]$root.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
    $root.Controls.Add($tabs, 0, $rr)
    $tp1 = New-Object Windows.Forms.TabPage 'Befunde (Fehler / Warnungen)'
    $tp2 = New-Object Windows.Forms.TabPage 'Alle geprüften Werte'
    $tp3 = New-Object Windows.Forms.TabPage 'Protokoll'
    $tabs.TabPages.AddRange(@($tp1, $tp2, $tp3))

    $tt = New-Object Windows.Forms.ToolTip
    $tt.SetToolTip($tbHost, 'IP-Adresse oder Hostname des iLO. Mehrere Server mit Komma oder Semikolon trennen.')
    $tt.SetToolTip($cbRoot, 'Komplett = alle OIDs des Agents; "Nur HPE" ist schneller und reicht für die Auswertung.')

    function New-List($Page, [object[]]$Cols) {
        $lv = New-Object Windows.Forms.ListView
        $lv.Dock = 'Fill'; $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.GridLines = $true
        $lv.ShowGroups = $true; $lv.HideSelection = $false
        foreach ($c in $Cols) { [void]$lv.Columns.Add($c[0], (Sc $c[1])) }
        $Page.Controls.Add($lv)
        return $lv
    }
    $lvF = New-List $tp1 @(@('Stufe', 80), @('Komponente', 190), @('Instanz', 290), @('Status', 210), @('Empfehlung', 300))
    $lvA = New-List $tp2 @(@('Stufe', 80), @('Komponente', 200), @('Instanz', 290), @('Status', 220), @('OID', 260))
    $tbLog = New-Object Windows.Forms.TextBox
    $tbLog.Multiline = $true; $tbLog.ScrollBars = 'Vertical'; $tbLog.ReadOnly = $true; $tbLog.Dock = 'Fill'
    $tbLog.Font = New-Object Drawing.Font('Consolas', 9); $tbLog.BackColor = [Drawing.Color]::White
    $tp3.Controls.Add($tbLog)

    # Kontextmenü: Kopieren
    $cm = New-Object Windows.Forms.ContextMenuStrip
    $miCopy = $cm.Items.Add('Markierte Zeilen kopieren')
    $lvF.ContextMenuStrip = $cm; $lvA.ContextMenuStrip = $cm

    # ---------------------------------------------------------------- Logik
    $script:LastHtml = $null
    $script:Running = $false

    $log = {
        param([string]$m)
        $tbLog.AppendText(('[{0:HH:mm:ss}] {1}' -f (Get-Date), $m) + [Environment]::NewLine)
    }

    $updateV3 = {
        $v3 = ($cbVer.SelectedItem -eq '3')
        $gb2.Enabled = $v3
        $tbComm.Enabled = -not $v3; $chkShow.Enabled = -not $v3
        $lvl = [string]$cbLvl.SelectedItem
        $cbAuth.Enabled = ($lvl -ne 'noAuthNoPriv'); $tbAuth.Enabled = ($lvl -ne 'noAuthNoPriv')
        $cbPriv.Enabled = ($lvl -eq 'authPriv'); $tbPriv.Enabled = ($lvl -eq 'authPriv')
    }
    $cbVer.Add_SelectedIndexChanged($updateV3)
    $cbLvl.Add_SelectedIndexChanged($updateV3)
    & $updateV3
    $chkShow.Add_CheckedChanged({ $tbComm.UseSystemPasswordChar = -not $chkShow.Checked })

    $setRunning = {
        param([bool]$on)
        $script:Running = $on
        foreach ($c in @($gb1, $gb2, $tbOut, $btnOut, $btnStart, $btnFile)) { $c.Enabled = -not $on }
        if (-not $on) { & $updateV3 }
        $btnCancel.Enabled = $on
        if ($on) { $prg.Style = 'Marquee'; $prg.MarqueeAnimationSpeed = 30 }
        else { $prg.Style = 'Blocks'; $prg.Value = 100 }
        $form.Cursor = $(if ($on) { [Windows.Forms.Cursors]::AppStarting } else { [Windows.Forms.Cursors]::Default })
    }

    $addRow = {
        param($lv, $grp, [string[]]$cells, [string]$sev, $tag)
        $it = New-Object Windows.Forms.ListViewItem($cells[0])
        for ($i = 1; $i -lt $cells.Count; $i++) { [void]$it.SubItems.Add([string]$cells[$i]) }
        switch ($sev) {
            'CRIT' { $it.BackColor = $cRowCrit; $it.Font = $fBold }
            'WARN' { $it.BackColor = $cRowWarn }
            'OK'   { $it.BackColor = $cRowOk }
            'NA'   { $it.ForeColor = [Drawing.Color]::Gray }
            'ERR'  { $it.BackColor = $cRowCrit; $it.ForeColor = [Drawing.Color]::DarkRed }
        }
        $it.Group = $grp
        $it.Tag = $tag
        [void]$lv.Items.Add($it)
    }

    $sevLabel = @{ CRIT = 'Kritisch'; WARN = 'Warnung'; OK = 'OK'; NA = 'n.a.' }

    $showResult = {
        param($r)
        if ($r.Error) {
            $hdr = "$($r.Name)  –  FEHLER"
            $g1 = New-Object Windows.Forms.ListViewGroup($hdr); [void]$lvF.Groups.Add($g1)
            & $addRow $lvF $g1 @('Fehler', 'Verbindung / Walk', $r.Name, '', $r.Error) 'ERR' $null
            & $log "FEHLER $($r.Name): $($r.Error)"
            return
        }
        $ev = $r.Ev
        $srvLabel = $r.Name
        if ($ev.Info['Hostname']) { $srvLabel = "$($ev.Info['Hostname'])  ($($r.Name))" }
        $model = ''
        if ($ev.Info['Modell']) { $model = "  ·  $($ev.Info['Modell'])" }
        $hdr = '{0}{1}  –  {2}   ({3} kritisch, {4} Warnungen, {5} OK)' -f $srvLabel, $model, (Get-StatusText $ev.Code), $ev.Crit, $ev.Warn, $ev.Ok
        $g1 = New-Object Windows.Forms.ListViewGroup($hdr); [void]$lvF.Groups.Add($g1)
        $g2 = New-Object Windows.Forms.ListViewGroup($hdr); [void]$lvA.Groups.Add($g2)

        if ($ev.HpeCount -eq 0) {
            & $addRow $lvF $g1 @('Unbekannt', 'HPE-Agent', '-', 'keine HPE-Werte', 'AMS / Insight Agents installieren, SNMP im iLO prüfen') 'WARN' $r.Html
        } elseif ($ev.Findings.Count -eq 0) {
            & $addRow $lvF $g1 @('OK', 'Alle Komponenten', '-', 'keine Fehler oder Warnungen', '') 'OK' $r.Html
        } else {
            foreach ($f in $ev.Findings) {
                & $addRow $lvF $g1 @($sevLabel[$f.Stufe], $f.Komponente, $f.Instanz, "$($f.Bedeutung)  [$($f.Wert)]", $f.Empfehlung) $f.Stufe $r.Html
            }
        }
        foreach ($c in $ev.Checks) {
            & $addRow $lvA $g2 @($sevLabel[$c.Stufe], $c.Komponente, $c.Instanz, "$($c.Bedeutung)  [$($c.Wert)]", $c.OID) $c.Stufe $r.Html
        }
        $script:LastHtml = $r.Html
        $btnReport.Enabled = $true
        foreach ($k in $ev.Info.Keys) { & $log ("   {0,-14}: {1}" -f $k, $ev.Info[$k]) }
        & $log ("Ergebnis {0}: {1} – {2} kritisch, {3} Warnungen, {4} OK" -f $r.Name, (Get-StatusText $ev.Code), $ev.Crit, $ev.Warn, $ev.Ok)
        if ($r.Walk) { & $log "   Walk:    $($r.Walk)" }
        & $log "   Bericht: $($r.Html)"
    }

    $getCfg = {
        $root = '.1.3.6.1'
        if ($cbRoot.SelectedIndex -eq 1) { $root = '.1.3.6.1.4.1.232' }
        @{
            Version = [string]$cbVer.SelectedItem; Community = $tbComm.Text; User = $tbUser.Text.Trim()
            SecLevel = [string]$cbLvl.SelectedItem; AuthProtocol = [string]$cbAuth.SelectedItem; AuthPassword = $tbAuth.Text
            PrivProtocol = [string]$cbPriv.SelectedItem; PrivPassword = $tbPriv.Text
            Root = $root; Customer = $tbCust.Text.Trim(); OutDir = $tbOut.Text.Trim()
            Port = [int]$nuPort.Value; TimeoutSec = [int]$nuTo.Value; Retries = 2; MaxRepetitions = 25
        }
    }

    $btnStart.Add_Click({
            $targets = @($tbHost.Text.Split(',;') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (-not $targets) {
                [void][Windows.Forms.MessageBox]::Show($form, 'Bitte mindestens eine iLO-IP oder einen Hostnamen eingeben.', 'Eingabe fehlt', 'OK', 'Warning')
                $tbHost.Focus(); return
            }
            $cfg = & $getCfg
            if ($cfg.Version -eq '3') {
                $msg = $null
                if (-not $cfg.User) { $msg = 'Bitte den SNMPv3-Benutzer eingeben.' }
                elseif ($cfg.SecLevel -ne 'noAuthNoPriv' -and $cfg.AuthPassword.Length -lt 8) { $msg = 'Das Auth-Passwort muss mindestens 8 Zeichen haben.' }
                elseif ($cfg.SecLevel -eq 'authPriv' -and $cfg.PrivPassword.Length -lt 8) { $msg = 'Das Privacy-Passwort muss mindestens 8 Zeichen haben.' }
                if ($msg) { [void][Windows.Forms.MessageBox]::Show($form, $msg, 'SNMPv3', 'OK', 'Warning'); return }
            }
            $lvF.Items.Clear(); $lvF.Groups.Clear(); $lvA.Items.Clear(); $lvA.Groups.Clear()
            $script:CancelAll = $false
            & $setRunning $true
            $tabs.SelectedTab = $tp1
            try {
                $i = 0
                foreach ($t in $targets) {
                    if ($script:CancelAll) { break }
                    $i++
                    $prefix = '[{0}/{1}] {2}' -f $i, $targets.Count, $t
                    & $log "$prefix – Verbinde (SNMP v$($cfg.Version)) ..."
                    $lblStat.Text = "$prefix – Verbinde ..."
                    $tick = {
                        param($job)
                        if ($job.Phase -eq 'Walk') { $lblStat.Text = "$prefix – Walk läuft: $($job.Count) OIDs gelesen" }
                        [Windows.Forms.Application]::DoEvents()
                    }
                    $r = Invoke-HealthCheck -Name $t -Cfg $cfg -Tick $tick
                    if (-not $r.Error) { & $log ("$prefix – Walk fertig in {0} s" -f $r.Seconds) }
                    & $showResult $r
                    [Windows.Forms.Application]::DoEvents()
                }
                $nCrit = @($lvF.Items | Where-Object { $_.Text -eq 'Kritisch' }).Count
                $nWarn = @($lvF.Items | Where-Object { $_.Text -eq 'Warnung' }).Count
                $nErr = @($lvF.Items | Where-Object { $_.Text -eq 'Fehler' }).Count
                $lblStat.Text = "Fertig: $($targets.Count) Server – $nCrit kritisch, $nWarn Warnungen" + $(if ($nErr) { ", $nErr Verbindungsfehler" } else { '' })
            } catch {
                & $log "Unerwarteter Fehler: $($_.Exception.Message)"
                $lblStat.Text = 'Fehler – siehe Protokoll.'
            } finally {
                & $setRunning $false
                if ($script:CloseRequested) { $form.Close() }
            }
        })

    $btnCancel.Add_Click({
            $script:CancelAll = $true
            if ($script:CurrentClient) { $script:CurrentClient.CancelRequested = $true }
            $lblStat.Text = 'Abbruch angefordert ...'
        })

    $btnFile.Add_Click({
            $dlg = New-Object Windows.Forms.OpenFileDialog
            $dlg.Title = 'Walk-Datei auswählen'
            $dlg.Filter = 'Walk-Dateien (*.txt)|*.txt|Alle Dateien (*.*)|*.*'
            $dlg.Multiselect = $true
            if (Test-Path $tbOut.Text) { $dlg.InitialDirectory = $tbOut.Text }
            if ($dlg.ShowDialog($form) -ne 'OK') { return }
            $cfg = & $getCfg
            $lvF.Items.Clear(); $lvF.Groups.Clear(); $lvA.Items.Clear(); $lvA.Groups.Clear()
            & $setRunning $true
            try {
                foreach ($f in $dlg.FileNames) {
                    $n = [IO.Path]::GetFileNameWithoutExtension($f)
                    & $log "Werte Datei aus: $f"
                    $lblStat.Text = "Werte $n aus ..."
                    [Windows.Forms.Application]::DoEvents()
                    $r = Invoke-HealthCheck -Name $n -Cfg $cfg -File $f
                    & $showResult $r
                }
                $lblStat.Text = 'Auswertung abgeschlossen.'
            } finally { & $setRunning $false }
        })

    $btnOut.Add_Click({
            $dlg = New-Object Windows.Forms.FolderBrowserDialog
            $dlg.Description = 'Ordner für Walk-Dateien und Berichte'
            if (Test-Path $tbOut.Text) { $dlg.SelectedPath = $tbOut.Text }
            if ($dlg.ShowDialog($form) -eq 'OK') { $tbOut.Text = $dlg.SelectedPath }
        })

    $btnReport.Add_Click({ if ($script:LastHtml -and (Test-Path $script:LastHtml)) { Start-Process $script:LastHtml } })

    $btnFolder.Add_Click({
            $d = $tbOut.Text
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            Start-Process explorer.exe $d
        })

    $openRowReport = {
        param($lv)
        if ($lv.SelectedItems.Count -and $lv.SelectedItems[0].Tag -and (Test-Path $lv.SelectedItems[0].Tag)) { Start-Process $lv.SelectedItems[0].Tag }
    }
    $lvF.Add_DoubleClick({ & $openRowReport $lvF })
    $lvA.Add_DoubleClick({ & $openRowReport $lvA })

    $miCopy.Add_Click({
            $lv = $cm.SourceControl
            if (-not $lv -or $lv.SelectedItems.Count -eq 0) { return }
            $sb = New-Object Text.StringBuilder
            foreach ($it in $lv.SelectedItems) {
                $cells = @(); foreach ($s in $it.SubItems) { $cells += $s.Text }
                [void]$sb.AppendLine(($cells -join "`t"))
            }
            [Windows.Forms.Clipboard]::SetText($sb.ToString())
        })

    $tbHost.Add_KeyDown({ if ($_.KeyCode -eq 'Enter' -and $btnStart.Enabled) { $btnStart.PerformClick(); $_.SuppressKeyPress = $true } })

    $script:CloseRequested = $false
    $form.Add_FormClosing({
            if ($script:Running) {
                $_.Cancel = $true
                $script:CloseRequested = $true
                $script:CancelAll = $true
                if ($script:CurrentClient) { $script:CurrentClient.CancelRequested = $true }
                $lblStat.Text = 'Wird abgebrochen – Fenster schließt gleich ...'
            }
        })

    $form.Add_Shown({ $tbHost.Focus() })
    & $log "Bereit. Ausgabeordner: $($tbOut.Text)"
    [void]$form.ShowDialog()
    $form.Dispose()
}

# =============================================================================
#  Start
# =============================================================================
if ($GuiMode) {
    try {
        Initialize-Engine
        Show-Gui
    } catch {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.MessageBox]::Show(
            "Das Tool konnte nicht gestartet werden:`n`n$($_.Exception.Message)`n`nHinweis: Add-Type kann durch AppLocker / Constrained Language Mode gesperrt sein.",
            'HPE SNMP-Healthcheck', 'OK', 'Error')
        exit 3
    }
    exit 0
}

# ---------------------------------------------------------------- Kommandozeile
try { Initialize-Engine }
catch { Write-Host " SNMP-Engine konnte nicht geladen werden: $($_.Exception.Message)" -ForegroundColor Red; exit 3 }

if (-not $OutDir) { $OutDir = Get-DefaultOutDir }
$cfg = @{
    Version = $Version; Community = $Community; User = $User; SecLevel = $SecLevel
    AuthProtocol = $AuthProtocol; AuthPassword = $AuthPassword; PrivProtocol = $PrivProtocol; PrivPassword = $PrivPassword
    Root = $Root; Customer = $Customer; OutDir = $OutDir; Port = $Port; TimeoutSec = $TimeoutSec
    Retries = $Retries; MaxRepetitions = $MaxRepetitions
}

$Overall = 0
$jobs = @()
if ($AnalyzeFile) { $jobs += [pscustomobject]@{ Name = [IO.Path]::GetFileNameWithoutExtension($AnalyzeFile); File = (Resolve-Path $AnalyzeFile).Path } }
else { foreach ($t in $Target) { $jobs += [pscustomobject]@{ Name = $t; File = $null } } }

foreach ($j in $jobs) {
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkGray
    Write-Host " HPE ProLiant Healthcheck – $($j.Name)" -ForegroundColor White
    Write-Host ('=' * 100) -ForegroundColor DarkGray
    $label = $j.Name
    $tick = { param($job) Write-Progress -Activity "SNMP-Walk $label" -Status "$($job.Phase): $($job.Count) OIDs gelesen" }
    if ($j.File) { $r = Invoke-HealthCheck -Name $j.Name -Cfg $cfg -File $j.File }
    else { $r = Invoke-HealthCheck -Name $j.Name -Cfg $cfg -Tick $tick }
    Write-Progress -Activity "SNMP-Walk $label" -Completed

    if ($r.Error) {
        Write-Host " FEHLER: $($r.Error)" -ForegroundColor Red
        $Overall = [math]::Max($Overall, 3)
        continue
    }
    $ev = $r.Ev
    foreach ($k in $ev.Info.Keys) { Write-Host (' {0,-14}: {1}' -f $k, $ev.Info[$k]) }
    Write-Host ''
    Write-Host (' Geprüft: {0}  ' -f $ev.Checks.Count) -NoNewline
    Write-Host ('OK: {0}  ' -f $ev.Ok) -ForegroundColor Green -NoNewline
    Write-Host ('Warnung: {0}  ' -f $ev.Warn) -ForegroundColor Yellow -NoNewline
    Write-Host ('Kritisch: {0}  ' -f $ev.Crit) -ForegroundColor Red -NoNewline
    Write-Host ('n.a.: {0}' -f $ev.Na) -ForegroundColor DarkGray
    Write-Host ''
    if ($ev.HpeCount -eq 0) {
        Write-Host ' UNBEKANNT: Keine HPE-Statuswerte gefunden – AMS / Insight Agents und SNMP im iLO prüfen.' -ForegroundColor Yellow
    } elseif ($ev.Findings.Count -eq 0) {
        Write-Host ' Keine Warnungen oder Fehler gefunden.' -ForegroundColor Green
    } else {
        Write-Host ' WERTE MIT FEHLER / WARNUNG' -ForegroundColor White
        foreach ($f in $ev.Findings) {
            $col = 'Yellow'; if ($f.Stufe -eq 'CRIT') { $col = 'Red' }
            Write-Host (' {0,-5} ' -f $f.Stufe) -ForegroundColor $col -NoNewline
            Write-Host ('{0,-30} {1,-42} {2} – {3}' -f $f.Komponente, $f.Instanz, $f.Wert, $f.Bedeutung)
        }
    }
    Write-Host ''
    if ($r.Walk) { Write-Host " Walk:    $($r.Walk)" }
    Write-Host " Bericht: $($r.Html)"
    if ($ev.Code -gt $Overall) { $Overall = $ev.Code }
}
Write-Host ''
Write-Host (' Gesamtstatus: {0}' -f (Get-StatusText $Overall)) -ForegroundColor $(switch ($Overall) { 0 { 'Green' } 1 { 'Yellow' } 2 { 'Red' } default { 'Magenta' } })
exit $Overall
