#requires -Version 2.0
<#
    Tunnel443.ps1  -  SSH over 443 + badvpn-compatible UDP gateway, pure Windows / .NET
    ==============================================================================
    Replaces, on Windows and without docker, these two pieces of Run.sh:
        udocker run dweomer/stunnel  (stunnel :443 -> 127.0.0.1:22)
        ./udpgw/server -port 7300    (UDP over the tunnel for games / DNS / calls)

    Part 1 : TLS/plain listener on <BindIp>:<Port> forwarding to 127.0.0.1:<TargetPort>
             - BindIp is the detected physical NIC, never the VPN/TUN adapter
             - outbound UDP sockets are bound to the same IP AND pinned to the same
               NIC by index (IP_UNICAST_IF) - a TUN default route cannot steal them
             - first byte 0x16  -> real TLS handshake (HTTP Custom "TLS + SNI")
             - anything else    -> transparent pass-through (raw ssh on 443)
    Part 2 : UDP gateway on <UdpGwPort> (default 127.0.0.1:7300, reached through
             the ssh tunnel). Speaks the badvpn udpgw protocol:
             [2 byte LITTLE endian length][1 byte flags][2 byte conid][addr][data]

    No Docker, no stunnel, no Go, no Python - only Windows + .NET Framework.
#>

[CmdletBinding()]
param(
    [int]    $Port            = 443,
    [string] $TargetHost      = '127.0.0.1',
    [int]    $TargetPort      = 22,
    [string] $CertThumbprint  = '',
    [string] $CertSubject     = 'CN=ssh443-tunnel',
    [string] $SniHost         = '',
    [string] $LogFile         = 'C:\ProgramData\ssh443\tunnel.log',
    [int]    $PeekMs          = 2000,
    [int]    $StatusInterval  = 300,
    [int]    $UdpGwPort       = 7300,
    [string] $UdpGwBind       = '127.0.0.1',
    [string] $UdpGwDns        = '',
    [string] $BindIp          = '',
    [int]    $BindIfIndex     = 0,
    [string] $BindGateway     = '',
    [string] $DnsServers      = '',
    [string] $RouteStateFile  = '',
    [int]    $RouteGuardInterval = 10,
    [string] $BindNicDll      = '',
    [switch] $NoSshdBind,
    [switch] $UdpGwVerbose,
    [switch] $NoAutoDetect
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 6) { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
if (-not $SniHost) { $SniHost = 'localhost' }

# ================================================================== C# core
$cs = @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Ssh443
{
    // ------------------------------------------------------------------ logger
    public class Log
    {
        private static object _lock = new object();
        public static string File = null;
        public static long MaxBytes = 8 * 1024 * 1024;   // rotate at 8 MB
        public static void Write(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg;
            if (File != null && File.Length > 0)
            {
                try
                {
                    lock (_lock)
                    {
                        try
                        {
                            System.IO.FileInfo fi = new System.IO.FileInfo(File);
                            if (fi.Exists && fi.Length > MaxBytes)
                            {
                                string old = File + ".1";
                                if (System.IO.File.Exists(old)) System.IO.File.Delete(old);
                                System.IO.File.Move(File, old);
                            }
                        }
                        catch { }
                        System.IO.File.AppendAllText(File, line + Environment.NewLine);
                    }
                }
                catch { }
            }
            try { Console.WriteLine(line); } catch { }
        }
    }

    // ================================================================== TCP TLS tunnel (stunnel replacement)
    public class Tunnel
    {
        public static volatile bool StopIt = false;
        public static string TargetHost = "127.0.0.1";
        public static int    TargetPort = 22;
        public static X509Certificate2 Cert = null;
        public static bool   AutoDetect = true;
        public static int    PeekMs = 2000;
        public static string BindIp = "";      // physical NIC only; never the TUN adapter

        public static long ConnTotal = 0, ConnTls = 0, ConnPlain = 0, ConnActive = 0, Errs = 0;
        public static long BytesUp = 0, BytesDown = 0;

        private static Socket _listener = null;

        private static bool AcceptAny(object sender, X509Certificate certificate,
                                      X509Chain chain, SslPolicyErrors errors) { return true; }

        public static X509Certificate2 LoadCert(string thumbOrPath)
        {
            if (thumbOrPath == null || thumbOrPath.Length == 0)
                throw new Exception("No certificate supplied.");

            if (System.IO.File.Exists(thumbOrPath))
                return new X509Certificate2(thumbOrPath, "", X509KeyStorageFlags.MachineKeySet);

            string t = thumbOrPath.Replace(" ", "").ToUpperInvariant();
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            try
            {
                foreach (X509Certificate2 c in store.Certificates)
                    if (string.Equals(c.Thumbprint, t, StringComparison.OrdinalIgnoreCase)) return c;
            }
            finally { store.Close(); }
            throw new Exception("Certificate " + thumbOrPath + " not found in LocalMachine\\My");
        }

        public static Socket ListenAny(string bindIp, int port, int backlog)
        {
            IPAddress ip = IPAddress.Any;
            if (bindIp != null && bindIp.Length > 0) IPAddress.TryParse(bindIp, out ip);

            Socket s;
            if (ip.Equals(IPAddress.Any))
            {
                try
                {
                    s = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    s.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                    s.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                }
                catch (Exception)
                {
                    s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    s.Bind(new IPEndPoint(IPAddress.Any, port));
                }
            }
            else
            {
                s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                s.Bind(new IPEndPoint(ip, port));
            }
            s.Listen(backlog);
            return s;
        }

        public static void Start(string thumb, string targetHost, int targetPort, int port,
                                 string logFile, bool autoDetect, int peekMs, string bindIp)
        {
            TargetHost = targetHost; TargetPort = targetPort;
            AutoDetect = autoDetect; PeekMs = peekMs;
            BindIp = (bindIp == null) ? "" : bindIp.Trim();

            Cert = LoadCert(thumb);
            Log.Write("cert        : " + Cert.Subject + "  [" + Cert.Thumbprint + "]  until " + Cert.NotAfter.ToString("yyyy-MM-dd"));

            // bind to the real internet card only (0.0.0.0 means "all adapters",
            // which includes the VPN TUN -> recursive loop).
            _listener = ListenAny(BindIp, port, 1024);
            string shown = BindIp.Length == 0 ? "0.0.0.0" : BindIp;
            Log.Write("tcp listen  : " + shown + ":" + port + (BindIp.Length == 0 ? " (all adapters)" : " (physical NIC only)") + "  ->  " + targetHost + ":" + targetPort);
            Log.Write("tcp mode    : " + (autoDetect ? "auto (TLS + plain TCP)" : "TLS only"));

            Thread t = new Thread(new ThreadStart(AcceptLoop));
            t.IsBackground = true; t.Name = "ssh443-accept"; t.Start();
        }

        public static void Stop()
        {
            StopIt = true;
            try { if (_listener != null) _listener.Close(); } catch { }
        }

        private static void AcceptLoop()
        {
            while (!StopIt)
            {
                Socket c = null;
                try { c = _listener.Accept(); }
                catch (Exception) { if (StopIt) break; Thread.Sleep(250); continue; }

                try
                {
                    c.NoDelay = true;
                    Thread w = new Thread(new ParameterizedThreadStart(Handle));
                    w.IsBackground = true; w.Name = "ssh443-conn"; w.Start(c);
                }
                catch (Exception) { Interlocked.Increment(ref Errs); try { c.Close(); } catch { } }
            }
        }

        private static void Handle(object state)
        {
            Socket c = (Socket)state;
            string peer = "?";
            try { peer = c.RemoteEndPoint.ToString(); } catch { }

            Interlocked.Increment(ref ConnTotal);
            Interlocked.Increment(ref ConnActive);

            Socket back = null;
            try
            {
                bool tls;
                if (AutoDetect)
                {
                    byte[] one = new byte[1];
                    int n = 0;
                    try { c.ReceiveTimeout = PeekMs; n = c.Receive(one, 0, 1, SocketFlags.Peek); }
                    catch (SocketException) { n = 0; }
                    tls = (n == 1 && one[0] == 0x16);
                }
                else tls = true;
                try { c.ReceiveTimeout = 0; } catch { }

                Stream client;
                if (tls)
                {
                    Interlocked.Increment(ref ConnTls);
                    SslStream ssl = new SslStream(new NetworkStream(c, false), false,
                        new RemoteCertificateValidationCallback(AcceptAny));
                    ssl.AuthenticateAsServer(Cert, false,
                        SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls, false);
                    client = ssl;
                }
                else { Interlocked.Increment(ref ConnPlain); client = new NetworkStream(c, false); }

                back = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                back.NoDelay = true;
                back.Connect(TargetHost, TargetPort);
                Stream server = new NetworkStream(back, false);

                // Connecting to 127.0.0.1:22 makes OpenSSH spawn a NEW sshd child
                // for this session. Pin it to the physical NIC right now, before
                // it can open the first SOCKS/direct-tcpip socket via the TUN.
                BindNic.InjectAllNow();

                Log.Write("open        : " + peer + "  " + (tls ? "TLS" : "TCP"));

                Stream[] from = new Stream[] { client, server };
                Stream[] to   = new Stream[] { server, client };
                Socket[] sk   = new Socket[] { back, c };
                Thread t1 = new Thread(new ThreadStart(delegate { Pump(from[0], to[0], sk[0], 0); }));
                Thread t2 = new Thread(new ThreadStart(delegate { Pump(from[1], to[1], sk[1], 1); }));
                t1.IsBackground = true; t2.IsBackground = true;
                t1.Start(); t2.Start(); t1.Join(); t2.Join();
                Log.Write("close       : " + peer);
            }
            catch (Exception ex) { Interlocked.Increment(ref Errs); Log.Write("error       : " + peer + " : " + ex.Message); }
            finally
            {
                try { if (back != null) back.Close(); } catch { }
                try { c.Close(); } catch { }
                Interlocked.Decrement(ref ConnActive);
            }
        }

        private static void Pump(Stream from, Stream to, Socket toSock, int dir)
        {
            byte[] buf = new byte[65536];
            try
            {
                while (true)
                {
                    int n = from.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    to.Write(buf, 0, n); to.Flush();
                    if (dir == 0) Interlocked.Add(ref BytesUp, n); else Interlocked.Add(ref BytesDown, n);
                }
            }
            catch (Exception) { }
            try { if (toSock != null) toSock.Shutdown(SocketShutdown.Send); } catch { }
        }

        public static string Stats()
        {
            return "conn=" + Interlocked.Read(ref ConnTotal) + " tls=" + Interlocked.Read(ref ConnTls)
                 + " plain=" + Interlocked.Read(ref ConnPlain) + " active=" + Interlocked.Read(ref ConnActive)
                 + " up=" + (Interlocked.Read(ref BytesUp) / 1024) + "KB down=" + (Interlocked.Read(ref BytesDown) / 1024) + "KB"
                 + " err=" + Interlocked.Read(ref Errs);
        }
    }

    // ================================================================== UDP gateway (badvpn udpgw replacement)
    // wire format, each message prefixed with a 2 byte LITTLE endian length
    // (badvpn PacketProto):
    //   [len:2 LE][flags:1][conid:2][addr:4|16][port:2][payload...]
    //   flags: 1=keepalive  2=rebind  4=dns  8=ipv6
    public class UdpGw
    {
        public const int FLAG_KEEPALIVE = 1;
        public const int FLAG_REBIND    = 2;
        public const int FLAG_DNS       = 4;
        public const int FLAG_IPV6      = 8;

        public static volatile bool StopIt = false;
        public static volatile bool Verbose = false;
        public static int MaxConnsPerSession = 256;
        public static int IdleTimeoutMs = 120000;
        public static string DnsHost = "";
        public static int DnsPort = 53;
        public static string OutBindIp = "";   // source IP for outbound UDP (physical NIC)
        public static int    OutIfIndex = 0;   // force outgoing UDP onto this NIC via IP_UNICAST_IF

        public static long Sessions = 0, ConnTotal = 0, ConnActive = 0, PktsUp = 0, PktsDown = 0, Errs = 0;

        private static Socket _listener = null;
        private static List<Session> _sessions = new List<Session>();

        private class Session
        {
            public Socket Tcp;
            public Stream S;
            public object SendLock = new object();
            public Dictionary<int, Conn> Conns = new Dictionary<int, Conn>();
            public string Peer = "?";
            public bool KeepaliveLogged = false;
        }

        private class Conn
        {
            public Session Owner;
            public int ConId;
            public Socket Udp;
            public IPEndPoint Remote;      // address the client asked for (echoed back)
            public IPEndPoint SendTo;      // address we actually send to (dns override)
            public Thread Rx;
            public long Last;
            public bool Logged = false;   // log the first datagram of each connection
            public volatile bool Dead = false;
        }

        public static void Start(string bindIp, int port, string dnsHost)
        {
            if (port <= 0) return;
            DnsHost = dnsHost != null ? dnsHost : "";

            IPAddress ip = IPAddress.Loopback;
            if (bindIp != null && bindIp.Length > 0 && !IPAddress.TryParse(bindIp, out ip)) ip = IPAddress.Loopback;
            if (bindIp == "" || bindIp == "0.0.0.0" || bindIp == "*") ip = IPAddress.Any;

            _listener = Tunnel.ListenAny(ip.Equals(IPAddress.Any) ? null : ip.ToString(), port, 128);
            Log.Write("udpgw listen: " + ip.ToString() + ":" + port + (DnsHost.Length > 0 ? "  dns=" + DnsHost + ":" + DnsPort : ""));
            if (DnsHost.Length > 0)
                Log.Write("udpgw dns   : " + DnsHost + ":" + DnsPort + " (persisted physical NIC resolver - not TUN DNS)");

            Thread t = new Thread(new ThreadStart(AcceptLoop));
            t.IsBackground = true; t.Name = "udpgw-accept"; t.Start();
        }

        public static void Stop()
        {
            StopIt = true;
            try { if (_listener != null) _listener.Close(); } catch { }
            List<Session> copy;
            lock (_sessions) { copy = new List<Session>(_sessions); }
            foreach (Session s in copy) { try { s.Tcp.Close(); } catch { } }
        }

        private static void AcceptLoop()
        {
            while (!StopIt)
            {
                Socket c = null;
                try { c = _listener.Accept(); }
                catch (Exception) { if (StopIt) break; Thread.Sleep(250); continue; }

                Session s = new Session();
                s.Tcp = c;
                try { s.Peer = c.RemoteEndPoint.ToString(); } catch { }
                s.S = new NetworkStream(c, false);
                lock (_sessions) { _sessions.Add(s); }
                Interlocked.Increment(ref Sessions);

                Thread w = new Thread(new ParameterizedThreadStart(SessionLoop));
                w.IsBackground = true; w.Name = "udpgw-session"; w.Start(s);
            }
        }

        private static string Hex(byte[] b, int off, int len)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < len; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(b[off + i].ToString("X2"));
            }
            return sb.ToString();
        }

        private static bool ReadExact(Stream s, byte[] buf, int len)
        {
            int off = 0;
            while (off < len)
            {
                int n = s.Read(buf, off, len - off);
                if (n <= 0) return false;
                off += n;
            }
            return true;
        }

        private static void SessionLoop(object o)
        {
            Session ses = (Session)o;
            byte[] lenb = new byte[2];
            byte[] buf = new byte[65536];
            Log.Write("udpgw open  : " + ses.Peer);

            try
            {
                while (!StopIt)
                {
                    if (!ReadExact(ses.S, lenb, 2)) break;
                    // PacketProto length is LITTLE endian (badvpn: protocol/packetproto.h,
                    // "a 16-bit little-endian unsigned integer representing the length").
                    int len = lenb[0] | (lenb[1] << 8);
                    if (len < 3 || len > buf.Length) { Log.Write("udpgw bad len " + len + " from " + ses.Peer); break; }
                    if (!ReadExact(ses.S, buf, len)) break;
                    if (Verbose) Log.Write("udpgw recv  : " + ses.Peer + " flags=0x" + buf[0].ToString("X2")
                        + " conid=" + (buf[1] | (buf[2] << 8)) + " len=" + len + " hex=" + Hex(buf, 0, len < 16 ? len : 16));
                    Message(ses, buf, len);
                }
            }
            catch (Exception ex) { Interlocked.Increment(ref Errs); Log.Write("udpgw err   : " + ses.Peer + " : " + ex.Message); }
            finally
            {
                lock (_sessions) { _sessions.Remove(ses); }
                lock (ses.Conns)
                {
                    foreach (KeyValuePair<int, Conn> kv in ses.Conns)
                    {
                        kv.Value.Dead = true;
                        try { kv.Value.Udp.Close(); } catch { }
                    }
                    ses.Conns.Clear();
                }
                try { ses.Tcp.Close(); } catch { }
                Log.Write("udpgw close : " + ses.Peer);
            }
        }

        private static bool IsUnroutable(IPAddress a)
        {
            byte[] b = a.GetAddressBytes();
            if (a.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 0 || b[0] == 10 || b[0] == 127) return true;
                if (b[0] == 169 && b[1] == 254) return true;                    // link local
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                if (b[0] == 192 && b[1] == 168) return true;
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;      // CGNAT
                if (b[0] >= 224) return true;                                   // multicast/reserved
                return false;
            }
            if (a.Equals(IPAddress.IPv6Loopback)) return true;
            if ((b[0] & 0xFE) == 0xFC) return true;                             // fc00::/7
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;             // fe80::/10
            for (int i = 0; i < b.Length; i++) { if (b[i] != 0) return false; }
            return true;
        }

        private static IPEndPoint ParseEndpoint(int flags, byte[] b, int pos)
        {
            bool v6 = (flags & FLAG_IPV6) != 0;
            if (v6)
            {
                byte[] a = new byte[16];
                Array.Copy(b, pos, a, 0, 16);
                int p = (b[pos + 16] << 8) | b[pos + 17];
                return new IPEndPoint(new IPAddress(a), p);
            }
            else
            {
                byte[] a = new byte[4];
                Array.Copy(b, pos, a, 0, 4);
                int p = (b[pos + 4] << 8) | b[pos + 5];
                return new IPEndPoint(new IPAddress(a), p);
            }
        }

        private static void Message(Session ses, byte[] b, int len)
        {
            int flags = b[0];
            int conid = b[1] | (b[2] << 8);   // badvpn header conid is LITTLE endian
            int pos = 3;

            if ((flags & FLAG_KEEPALIVE) != 0)
            {
                if (!ses.KeepaliveLogged)
                {
                    ses.KeepaliveLogged = true;
                    Log.Write("udpgw keepalive: " + ses.Peer + " (client confirmed UDPGW protocol)");
                }
                if (Verbose) Log.Write("udpgw keepalive: conid=" + conid + " len=" + len);
                return;
            }

            int addrLen = (flags & FLAG_IPV6) != 0 ? 18 : 6;
            if (pos + addrLen > len) { Interlocked.Increment(ref Errs); Log.Write("udpgw badpkt: flags=0x" + flags.ToString("X2") + " len=" + len + " hex=" + Hex(b, 0, len)); return; }

            IPEndPoint orig = ParseEndpoint(flags, b, pos);
            pos += addrLen;
            int dataLen = len - pos;

            IPEndPoint sendTo = orig;
            bool dnsPacket = (orig.Port == 53) || ((flags & FLAG_DNS) != 0);
            if (DnsHost.Length > 0 && dnsPacket)
            {
                IPAddress dnsIp;
                // DNS flag  -> always handled by this server, like badvpn --transparent-dns
                // port 53   -> only when the client aimed at an address the server can
                //              never reach (mobile clients usually use their LAN router,
                //              e.g. 192.168.1.1, as their DNS server)
                if (IPAddress.TryParse(DnsHost, out dnsIp) &&
                    (((flags & FLAG_DNS) != 0) || IsUnroutable(orig.Address)))
                {
                    sendTo = new IPEndPoint(dnsIp, DnsPort);
                }
            }

            if (Verbose) Log.Write("udpgw data  : conid=" + conid + " flags=0x" + flags.ToString("X2")
                + " target=" + orig + " via=" + sendTo + (sendTo.Equals(orig) ? "" : " (dns-override)")
                + " dlen=" + dataLen + " hex=" + Hex(b, pos, dataLen < 12 ? dataLen : 12));

            Conn con = null;
            lock (ses.Conns)
            {
                ses.Conns.TryGetValue(conid, out con);
                bool need = (con == null) || con.Dead
                            || !con.SendTo.Equals(sendTo)
                            || ((flags & FLAG_REBIND) != 0 && !con.Remote.Equals(orig));

                if (need)
                {
                    if (con != null) { con.Dead = true; try { con.Udp.Close(); } catch { } ses.Conns.Remove(conid); }
                    con = NewConn(ses, conid, orig, sendTo);
                    if (con == null) return;
                    ses.Conns[conid] = con;
                }
                else con.Last = Environment.TickCount;
            }

            // One info line per UDP flow - makes "server doesn't support UDP"
            // diagnosable without turning on full packet logging.
            if (!con.Logged)
            {
                con.Logged = true;
                Log.Write("udpgw first : conid=" + con.ConId + " target=" + sendTo +
                          (sendTo.Equals(orig) ? "" : " (dns-override from " + orig + ")") +
                          " dlen=" + dataLen + " if=" + OutIfIndex);
            }

            try
            {
                con.Udp.SendTo(b, pos, dataLen, SocketFlags.None, sendTo);
                Interlocked.Increment(ref PktsUp);
            }
            catch (Exception ex) { Interlocked.Increment(ref Errs); Log.Write("udpgw sendto err: " + sendTo + " : " + ex.Message); }
        }

        private static Conn NewConn(Session ses, int conid, IPEndPoint orig, IPEndPoint sendTo)
        {
            if (ses.Conns.Count >= MaxConnsPerSession) return null;

            Socket u = null;
            try
            {
                u = new Socket(sendTo.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                u.ReceiveTimeout = 250;
                try { u.ReceiveBufferSize = 1024 * 1024; u.SendBufferSize = 1024 * 1024; } catch { }
                // Disable SIO_UDP_CONNRESET on Windows so ICMP Port Unreachable doesn't throw WSAECONNRESET (10054)
                try {
                    const int SIO_UDP_CONNRESET = -1744830452; // 0x9800000C
                    u.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, new byte[] { 0 });
                } catch { }
                IPAddress src = null;
                if (!string.IsNullOrEmpty(OutBindIp)) IPAddress.TryParse(OutBindIp, out src);
                if (src != null && src.AddressFamily == sendTo.AddressFamily)
                    u.Bind(new IPEndPoint(src, 0));
                else
                    u.Bind(new IPEndPoint(sendTo.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));

                // A bound source IP alone is NOT enough: with a TUN default route
                // Windows may still push these datagrams into the VPN (loop).
                // IP_UNICAST_IF pins the outgoing interface by index and wins over
                // the route table. Winsock wants the index in NETWORK byte order.
                if (OutIfIndex > 0)
                {
                    try
                    {
                        if (sendTo.AddressFamily == AddressFamily.InterNetwork)
                            u.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31 /* IP_UNICAST_IF */,
                                              IPAddress.HostToNetworkOrder(OutIfIndex));
                        else
                            u.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)16 /* IPV6_UNICAST_IF */,
                                              IPAddress.HostToNetworkOrder(OutIfIndex));
                    }
                    catch (Exception ex) { Log.Write("udpgw ifbind warn: " + ex.Message); }
                }

                Conn con = new Conn();
                con.Owner = ses; con.ConId = conid; con.Udp = u;
                con.Remote = orig; con.SendTo = sendTo; con.Last = Environment.TickCount;

                Thread rx = new Thread(new ParameterizedThreadStart(ReceiveLoop));
                rx.IsBackground = true; rx.Name = "udpgw-udp" + conid;
                con.Rx = rx;
                rx.Start(con);
                Interlocked.Increment(ref ConnTotal);
                Interlocked.Increment(ref ConnActive);
                return con;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref Errs);
                Log.Write("udpgw bind err: " + ex.Message);
                try { if (u != null) u.Close(); } catch { }
                return null;
            }
        }

        private static void ReceiveLoop(object o)
        {
            Conn con = (Conn)o;
            byte[] buf = new byte[65536];
            EndPoint any = new IPEndPoint(con.SendTo.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            bool v6 = con.Remote.AddressFamily == AddressFamily.InterNetworkV6;

            while (!con.Dead && !StopIt)
            {
                int n = 0;
                EndPoint from = any;
                try { n = con.Udp.ReceiveFrom(buf, ref from); }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.TimedOut)
                    {
                        if (Environment.TickCount - con.Last > IdleTimeoutMs) break;
                        continue;
                    }
                    if (se.SocketErrorCode == SocketError.ConnectionReset || se.NativeErrorCode == 10054)
                    {
                        continue;
                    }
                    break;
                }
                catch (Exception) { break; }

                if (n <= 0) continue;
                con.Last = Environment.TickCount;
                Interlocked.Increment(ref PktsDown);
                if (Verbose) Log.Write("udpgw reply : conid=" + con.ConId + " from=" + from + " bytes=" + n
                    + " hex=" + Hex(buf, 0, n < 12 ? n : 12) + " -> client " + con.Remote);
                try { SendToClient(con, buf, n, v6); }
                catch (Exception) { break; }
            }

            con.Dead = true;
            try { con.Udp.Close(); } catch { }
            Interlocked.Decrement(ref ConnActive);
            lock (con.Owner.Conns) { if (con.Owner.Conns.ContainsKey(con.ConId)) con.Owner.Conns.Remove(con.ConId); }
        }

        private static void SendToClient(Conn con, byte[] data, int len, bool v6)
        {
            byte[] ip = con.Remote.Address.GetAddressBytes();
            int total = 3 + (v6 ? 18 : 6) + len;
            byte[] outBuf = new byte[2 + total];
            outBuf[0] = (byte)(total & 0xFF);      // PacketProto length is little endian
            outBuf[1] = (byte)(total >> 8);
            outBuf[2] = (byte)(v6 ? FLAG_IPV6 : 0);
            outBuf[3] = (byte)(con.ConId & 0xFF);
            outBuf[4] = (byte)(con.ConId >> 8);
            Array.Copy(ip, 0, outBuf, 5, ip.Length);
            int pt = 5 + ip.Length;
            outBuf[pt]     = (byte)(con.Remote.Port >> 8);
            outBuf[pt + 1] = (byte)(con.Remote.Port & 0xFF);
            Array.Copy(data, 0, outBuf, pt + 2, len);

            lock (con.Owner.SendLock)
            {
                con.Owner.S.Write(outBuf, 0, outBuf.Length);
                con.Owner.S.Flush();
            }
        }

        public static string Stats()
        {
            return "sessions=" + Interlocked.Read(ref Sessions) + " conns=" + Interlocked.Read(ref ConnTotal)
                 + " live=" + Interlocked.Read(ref ConnActive)
                 + " up=" + Interlocked.Read(ref PktsUp) + "pkt down=" + Interlocked.Read(ref PktsDown) + "pkt"
                 + " err=" + Interlocked.Read(ref Errs);
        }
    }

    // ------------------------------------------------------------- sshd binder
    // OpenSSH creates a NEW sshd.exe child for every incoming connection.  Those
    // children are the processes that open the sockets for SOCKS / direct-tcpip
    // forwarding.  If nothing is done, Windows sends those sockets back through
    // the client's TUN default route (0.0.0.0/1 + 128.0.0.0/1) and the whole
    // tunnel recurses until the internet "dies".  This keeper injects
    // bindnic.dll into every sshd.exe process so each new socket is pinned to
    // the physical NIC (source IP + IP_UNICAST_IF) and bypasses the TUN.
    public static class BindNic
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, int size, uint type, uint prot);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int written);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr sa, int stack, IntPtr start, IntPtr param, uint flags, out int tid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, int size, uint type);
        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EnumProcessModules(IntPtr h, IntPtr[] modules, int size, out int needed);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        static extern int GetModuleFileNameEx(IntPtr h, IntPtr module, System.Text.StringBuilder name, int size);

        const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
        const uint PAGE_READWRITE = 0x4;
        const uint ACCESS_INJECT = 0x0438; // VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFO|CREATE_THREAD
        const uint ACCESS_SCAN   = 0x0410; // VM_READ|QUERY_INFO

        static string _dll = "";
        static Thread _keeper = null;
        static volatile bool _stop = false;
        static int _injected = 0;

        public static int Injected { get { return _injected; } }

        public static void StartKeeper(string dllPath)
        {
            if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath))
            {
                Log.Write("sshd binder : DLL not found (" + dllPath + ") - TUN loop protection OFF");
                return;
            }
            _dll = Path.GetFullPath(dllPath);
            if (_keeper != null) return;
            _stop = false;
            _keeper = new Thread(KeeperLoop);
            _keeper.IsBackground = true;
            _keeper.Start();
            Log.Write("sshd binder : watching sshd.exe -> " + _dll);
        }

        public static void StopKeeper() { _stop = true; }

        // Called from the connection-accept path: a fresh sshd child is spawned
        // at that exact moment, so inject it immediately instead of waiting for
        // the next keeper tick (the first SOCKS request can arrive very fast).
        public static void InjectAllNow()
        {
            if (string.IsNullOrEmpty(_dll)) return;
            try { InjectAll(); } catch { }
        }

        static void KeeperLoop()
        {
            while (!_stop)
            {
                try { InjectAll(); } catch { }
                Thread.Sleep(750);
            }
        }

        static bool IsInjected(int pid)
        {
            IntPtr h = OpenProcess(ACCESS_SCAN, false, pid);
            if (h == IntPtr.Zero) return true;   // cannot inspect - assume OK to avoid log spam
            try
            {
                IntPtr[] mods = new IntPtr[512];
                int needed = 0;
                if (!EnumProcessModules(h, mods, mods.Length * IntPtr.Size, out needed)) return false;
                int count = Math.Min(needed / IntPtr.Size, mods.Length);
                for (int i = 0; i < count; i++)
                {
                    StringBuilder sb = new StringBuilder(260);
                    if (GetModuleFileNameEx(h, mods[i], sb, sb.Capacity) > 0 &&
                        sb.ToString().EndsWith("bindnic.dll", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            finally { CloseHandle(h); }
        }

        static void InjectAll()
        {
            Process[] procs = Process.GetProcessesByName("sshd");
            foreach (Process p in procs)
            {
                try
                {
                    if (IsInjected(p.Id)) continue;
                    if (Inject(p.Id, _dll)) Log.Write("sshd binder : injected pid " + p.Id);
                }
                catch { }
                finally { p.Dispose(); }
            }
        }

        static bool Inject(int pid, string dll)
        {
            byte[] path = System.Text.Encoding.ASCII.GetBytes(dll + "\0");
            IntPtr h = OpenProcess(ACCESS_INJECT, false, pid);
            if (h == IntPtr.Zero) return false;
            IntPtr remote = IntPtr.Zero;
            try
            {
                remote = VirtualAllocEx(h, IntPtr.Zero, path.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (remote == IntPtr.Zero) return false;
                int written;
                if (!WriteProcessMemory(h, remote, path, path.Length, out written)) return false;
                IntPtr load = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (load == IntPtr.Zero) return false;
                int tid;
                IntPtr th = CreateRemoteThread(h, IntPtr.Zero, 0, load, remote, 0, out tid);
                if (th == IntPtr.Zero) return false;
                WaitForSingleObject(th, 5000);
                CloseHandle(th);
                Interlocked.Increment(ref _injected);
                return true;
            }
            finally
            {
                if (remote != IntPtr.Zero) VirtualFreeEx(h, remote, 0, MEM_RELEASE);
                CloseHandle(h);
            }
        }
    }
}
'@

if (-not ('Ssh443.BindNic' -as [type])) {
    Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
}

# ================================================================== logging
$logDir = Split-Path -Parent $LogFile
if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
[Ssh443.Log]::File = $LogFile

# ================================================================== primary NIC
# Run.ps1 passes everything explicitly; the state file is the SYSTEM-task fallback.
$nicFile = Join-Path $logDir 'primary-ip.txt'
$state   = @()
if (Test-Path $nicFile) { $state = @(Get-Content -LiteralPath $nicFile -ErrorAction SilentlyContinue) }
if ([string]::IsNullOrWhiteSpace($BindIp) -and $state.Count -gt 0) { $BindIp = $state[0].Trim() }
if ([string]::IsNullOrWhiteSpace($BindIp)) { $BindIp = '0.0.0.0' }
if ($BindIfIndex -le 0 -and $state.Count -gt 1) {
    $n = 0; if ([int]::TryParse($state[1].Trim(), [ref]$n)) { $BindIfIndex = $n }
}
if ([string]::IsNullOrWhiteSpace($BindGateway) -and $state.Count -gt 2) { $BindGateway = $state[2].Trim() }
$DnsList = @()
if (-not [string]::IsNullOrWhiteSpace($DnsServers)) {
    $DnsList = @($DnsServers.Split(',') | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() })
} elseif ($state.Count -gt 3 -and $state[3].Trim()) {
    $DnsList = @($state[3].Split(',') | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() })
}
if ([string]::IsNullOrWhiteSpace($RouteStateFile)) { $RouteStateFile = Join-Path $logDir 'samehost-routes.txt' }
[Ssh443.Log]::Write("bind ip     : $BindIp  (physical NIC only - TUN/VPN adapter excluded)")

# Resolve the interface index used by IP_UNICAST_IF. A bound source IP alone can
# still be routed into a TUN default route; pinning the NIC by index cannot.
if ($BindIfIndex -le 0 -and $BindIp -ne '0.0.0.0') {
    try {
        $a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindIp -ErrorAction SilentlyContinue |
             Select-Object -First 1
        if ($a) { $BindIfIndex = [int]$a.InterfaceIndex }
    } catch { }
}
if ($BindIfIndex -gt 0) { [Ssh443.UdpGw]::OutIfIndex = $BindIfIndex }
[Ssh443.Log]::Write("udp nic     : ifIndex $BindIfIndex  (IP_UNICAST_IF - bypass TUN)")
[Ssh443.Log]::Write("samehost    : gw=$BindGateway dns=$($DnsList -join ',') state=$RouteStateFile")

# --------------------------------------------------------- route guard (v1.9)
# NetMod installs 0.0.0.0/1 and 128.0.0.0/1 with metric 1 AFTER the tunnel is up.
# A more specific /32 route always wins, but it must still exist. Re-assert it
# every few seconds so reconnecting NetMod can never swallow our own IP, gateway
# or DNS resolver again. Only routes we created are recorded for clean uninstall.
function Get-SameHostRoutes {
    $list = New-Object System.Collections.Generic.List[object]
    if ($BindIp -ne '0.0.0.0') { $list.Add([pscustomobject]@{ Prefix = "$BindIp/32"; Hop = '' }) }
    if ($BindGateway) { $list.Add([pscustomobject]@{ Prefix = "$BindGateway/32"; Hop = '' }) }
    foreach ($d in $DnsList) {
        if ($d -eq $BindIp -or $d -eq $BindGateway) { continue }
        $list.Add([pscustomobject]@{ Prefix = "$d/32"; Hop = $BindGateway })
    }
    return $list
}
function Assert-SameHostRoutes {
    if ($BindIfIndex -le 0) { return }
    foreach ($r in (Get-SameHostRoutes)) {
        $wantHop = if ($r.Hop) { $r.Hop } else { '0.0.0.0' }
        $found = @(Get-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $BindIfIndex -ErrorAction SilentlyContinue |
                   Where-Object { $_.NextHop -eq $wantHop -and [int]$_.RouteMetric -le 1 })
        if ($found.Count -gt 0) { continue }
        try {
            if ($r.Hop) {
                New-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $BindIfIndex `
                    -NextHop $r.Hop -RouteMetric 1 -ErrorAction Stop | Out-Null
            } else {
                New-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $BindIfIndex `
                    -RouteMetric 1 -ErrorAction Stop | Out-Null
            }
            $line = "$($r.Prefix)|$BindIfIndex|$wantHop"
            $have = @()
            if (Test-Path $RouteStateFile) { $have = @(Get-Content -LiteralPath $RouteStateFile -ErrorAction SilentlyContinue) }
            if ($have -notcontains $line) { Add-Content -LiteralPath $RouteStateFile -Value $line -Encoding ASCII }
            [Ssh443.Log]::Write("route guard : added $($r.Prefix) via $wantHop if=$BindIfIndex")
        } catch {
            [Ssh443.Log]::Write("route guard : FAILED $($r.Prefix) via $wantHop - $($_.Exception.Message)")
        }
    }
}
Assert-SameHostRoutes

# ================================================================== sshd binder
# The SSH service forks a fresh sshd.exe per connection.  Those children open
# the outbound sockets for SOCKS/direct-tcpip and would otherwise follow the
# TUN default route straight back into this tunnel (infinite loop / no net).
# A background keeper pins each new sshd process to the physical NIC.
if (-not $NoSshdBind) {
    if ([string]::IsNullOrWhiteSpace($BindNicDll)) {
        $BindNicDll = Join-Path $PSScriptRoot 'native\bindnic.dll'
    }
    [Ssh443.BindNic]::StartKeeper($BindNicDll)
    [Ssh443.Log]::Write("sshd binder : v3 active - children injected while suspended at CreateProcess; details in " +
                        [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($BindNicDll), "bindnic.log"))
}

# ================================================================== certificate
if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
    $found = Get-ChildItem Cert:\LocalMachine\My |
             Where-Object { $_.Subject -eq $CertSubject } |
             Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($found) { $CertThumbprint = $found.Thumbprint }
    else {
        $CertThumbprint = (New-SelfSignedCertificate -DnsName $SniHost, 'localhost' -Subject $CertSubject `
            -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10) `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
            -Type SSLServerAuthentication).Thumbprint
    }
}

# ================================================================== dns for the udp gateway
# NEVER query the live adapter here: with a TUN connected it returns 10.4.2.2.
if ($UdpGwPort -gt 0) {
    if ([string]::IsNullOrWhiteSpace($UdpGwDns) -and $DnsList.Count -gt 0) { $UdpGwDns = $DnsList[0] }
    if ([string]::IsNullOrWhiteSpace($UdpGwDns)) {
        if ($state.Count -gt 1) {
            try {
                $dns = Get-DnsClientServerAddress -InterfaceIndex ([int]$state[1]) -AddressFamily IPv4 `
                       -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($dns -and $dns.ServerAddresses.Count -gt 0) { $UdpGwDns = $dns.ServerAddresses[0] }
            } catch { }
        }
    }
    if ([string]::IsNullOrWhiteSpace($UdpGwDns)) { $UdpGwDns = '1.1.1.1' }
}

# ================================================================== start
[Ssh443.Log]::Write("===== tunnel start  (pid $PID) =====")
try {
    [Ssh443.Tunnel]::Start($CertThumbprint, $TargetHost, $TargetPort, $Port, $LogFile, (-not $NoAutoDetect), $PeekMs, $BindIp)
} catch {
    [Ssh443.Log]::Write("FATAL       : cannot listen on port $Port -> $($_.Exception.Message)")
    Write-Host ''
    Write-Host "  [x] cannot listen on TCP $Port - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      another program is already using the port; stop it and start again." -ForegroundColor DarkGray
    Write-Host "      log: $LogFile"
    exit 1
}
[Ssh443.UdpGw]::Verbose = [bool]$UdpGwVerbose
[Ssh443.UdpGw]::OutBindIp = $BindIp
try {
    if ($UdpGwPort -gt 0) { [Ssh443.UdpGw]::Start($UdpGwBind, $UdpGwPort, $UdpGwDns) }
} catch {
    [Ssh443.Log]::Write("FATAL       : cannot start the UDP gateway on $UdpGwBind`:$UdpGwPort -> $($_.Exception.Message)")
    Write-Host "  [!] UDP gateway failed on $UdpGwBind`:$UdpGwPort - $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ''
Write-Host "  SSH-over-$Port tunnel is running." -ForegroundColor Green
Write-Host "  TLS/plain  : $BindIp`:$Port  ->  $TargetHost`:$TargetPort"
if ($UdpGwPort -gt 0) { Write-Host "  UDP gateway: $UdpGwBind`:$UdpGwPort  (dns $UdpGwDns)" }
Write-Host "  log        : $LogFile"
Write-Host '  Press Ctrl+C to stop.' -ForegroundColor DarkGray
Write-Host ''

$last = Get-Date
$lastRoute = Get-Date
try {
    while ($true) {
        Start-Sleep -Seconds 2
        if ($RouteGuardInterval -gt 0 -and ((Get-Date) - $lastRoute).TotalSeconds -ge $RouteGuardInterval) {
            $lastRoute = Get-Date
            Assert-SameHostRoutes
        }
        if (((Get-Date) - $last).TotalSeconds -ge $StatusInterval) {
            $last = Get-Date
            [Ssh443.Log]::Write('stats       : ' + [Ssh443.Tunnel]::Stats())
            if ($UdpGwPort -gt 0) { [Ssh443.Log]::Write('udpgw stats : ' + [Ssh443.UdpGw]::Stats()) }
        }
    }
}
finally {
    [Ssh443.Tunnel]::Stop()
    if ($UdpGwPort -gt 0) { [Ssh443.UdpGw]::Stop() }
    Write-Host 'stopped.' -ForegroundColor Yellow
}
