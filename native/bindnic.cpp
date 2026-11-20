// bindnic.dll  v3 - force every Winsock socket created in sshd.exe (and in any
// child process it spawns) out through ONE physical NIC.
//
// v2 -> v3 fixes (v2 still allowed a race on the very first forward):
//   1. CreateProcessW/A hook now creates each sshd child with CREATE_SUSPENDED,
//      injects bindnic.dll while the child is suspended, then resumes it. The
//      child therefore cannot open a single socket before its IAT is patched.
//   2. A maintenance thread re-scans loaded modules every 500 ms so a module
//      loaded after injection is still patched (no "late Winsock" hole).
//   3. Logging records the real destination, the forced source address, and the
//      forced interface index, so a live test can prove the bypass deterministically.
//   4. bindnic.cfg line 3 can set the log path; Run.ps1 grants Users write access
//      to the native folder, so a non-admin sshd child can always write the log.
//
// Hooks (IAT, matched against already-resolved function pointers so MSVC's
// ordinal imports are handled correctly):
//   socket / WSASocketA/W / connect / WSAConnect / sendto / WSASendTo
//   WSAIoctl (to wrap ConnectEx) / CreateProcessW / CreateProcessA
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define IP_UNICAST_IF_OPTION 31   // IPPROTO_IP, DWORD index in NETWORK byte order

static DWORD WINAPI MaintenanceThread(LPVOID);

static const GUID WSAID_CONNECTEX_LOCAL = {
    0x25a207b9, 0xddf3, 0x4660, { 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e }
};

static char  g_ip[64]        = { 0 };
static int   g_ifindex       = 0;
static char  g_dllpath[MAX_PATH] = { 0 };
static char  g_logpath[MAX_PATH] = { 0 };
static HMODULE g_hModule     = NULL;
static LONG  g_installed     = 0;
static LONG  g_maintStarted  = 0;
static CRITICAL_SECTION g_logCs;
static bool  g_logCsInit     = false;

// ---------------------------------------------------------------- diagnostics
static void Dbg(const char *fmt, ...)
{
    char path[MAX_PATH] = { 0 }, log[MAX_PATH] = { 0 };
    FILE *f = NULL;

    if (g_logpath[0]) {
        strncpy_s(log, MAX_PATH, g_logpath, _TRUNCATE);
    } else {
        HMODULE me = NULL;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)&Dbg, &me)) return;
        if (!GetModuleFileNameA(me, path, MAX_PATH)) return;
        strncpy_s(log, MAX_PATH, path, _TRUNCATE);
        char *slash = strrchr(log, '\\');
        if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - log), "bindnic.log");
        else return;
    }

    if (fopen_s(&f, log, "a") != 0 || !f) {
        char tmp[MAX_PATH] = { 0 };
        DWORD n = GetTempPathA(MAX_PATH, tmp);
        if (n && n < MAX_PATH) {
            strncpy_s(log, MAX_PATH, tmp, _TRUNCATE);
            strcat_s(log, MAX_PATH, "bindnic.log");
            fopen_s(&f, log, "a");
        }
    }
    if (!f) return;

    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, ap);
    va_end(ap);

    if (g_logCsInit) EnterCriticalSection(&g_logCs);
    fprintf(f, "[%5lu] %s\n", (unsigned long)GetCurrentProcessId(), line);
    fflush(f);
    if (g_logCsInit) LeaveCriticalSection(&g_logCs);
    fclose(f);
}

static const char *AddrText(const struct sockaddr *sa, char *out, size_t outlen)
{
    out[0] = 0;
    if (!sa) { strncpy_s(out, outlen, "-", _TRUNCATE); return out; }
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in sin;
        memcpy(&sin, sa, sizeof(sin));
        char ip[INET_ADDRSTRLEN] = { 0 };
        InetNtopA(AF_INET, &sin.sin_addr, ip, sizeof(ip));
        _snprintf_s(out, outlen, _TRUNCATE, "%s:%u", ip, (unsigned)ntohs(sin.sin_port));
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 s6;
        memcpy(&s6, sa, sizeof(s6));
        char ip[INET6_ADDRSTRLEN] = { 0 };
        InetNtopA(AF_INET6, &s6.sin6_addr, ip, sizeof(ip));
        _snprintf_s(out, outlen, _TRUNCATE, "[%s]:%u", ip, (unsigned)ntohs(s6.sin6_port));
    } else {
        _snprintf_s(out, outlen, _TRUNCATE, "af%d", (int)sa->sa_family);
    }
    return out;
}

static const char *LocalText(SOCKET s, char *out, size_t outlen)
{
    struct sockaddr_storage ss;
    int len = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(s, (struct sockaddr *)&ss, &len) == 0)
        return AddrText((struct sockaddr *)&ss, out, outlen);
    strncpy_s(out, outlen, "unbound", _TRUNCATE);
    return out;
}

// ---------------------------------------------------------------- function types
typedef int  (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int  (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int,
                                       LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int  (WSAAPI *PFN_sendto)(SOCKET, const char *, int, int,
                                   const struct sockaddr *, int);
typedef SOCKET (WSAAPI *PFN_socket)(int, int, int);
typedef SOCKET (WSAAPI *PFN_WSASocketA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef SOCKET (WSAAPI *PFN_WSASocketW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef int  (WSAAPI *PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                                      const struct sockaddr *, int,
                                      LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WSAAPI *PFN_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
                                     LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *PFN_ConnectEx)(SOCKET, const struct sockaddr *, int,
                                      LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR,
         LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
         LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR,
         LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
         LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static PFN_connect        pfn_connect        = NULL;
static PFN_WSAConnect     pfn_WSAConnect     = NULL;
static PFN_sendto         pfn_sendto         = NULL;
static PFN_socket         pfn_socket         = NULL;
static PFN_WSASocketA     pfn_WSASocketA     = NULL;
static PFN_WSASocketW     pfn_WSASocketW     = NULL;
static PFN_WSASendTo      pfn_WSASendTo      = NULL;
static PFN_WSAIoctl       pfn_WSAIoctl       = NULL;
static PFN_ConnectEx      pfn_ConnectEx      = NULL;
static PFN_CreateProcessW pfn_CreateProcessW = NULL;
static PFN_CreateProcessA pfn_CreateProcessA = NULL;

// ---------------------------------------------------------------- config
static void LoadConfig(void)
{
    HMODULE me = NULL;
    char path[MAX_PATH] = { 0 }, cfg[MAX_PATH] = { 0 };
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)&LoadConfig, &me)) return;
    g_hModule = me;
    if (!GetModuleFileNameA(me, path, MAX_PATH)) return;
    strncpy_s(g_dllpath, MAX_PATH, path, _TRUNCATE);
    strncpy_s(cfg, MAX_PATH, path, _TRUNCATE);

    char *slash = strrchr(cfg, '\\');
    if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - cfg), "bindnic.cfg");
    else return;

    FILE *f = NULL;
    if (fopen_s(&f, cfg, "r") != 0 || !f) return;
    char line[512] = { 0 };
    if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0]) strncpy_s(g_ip, sizeof(g_ip), line, _TRUNCATE);
    }
    line[0] = 0;
    if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        g_ifindex = atoi(line);
    }
    line[0] = 0;
    if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0]) strncpy_s(g_logpath, MAX_PATH, line, _TRUNCATE);
    }
    fclose(f);
    Dbg("loaded ip=%s if=%d log=%s", g_ip, g_ifindex, g_logpath[0] ? g_logpath : "(default)");
}

// ---------------------------------------------------------------- force bind
static void SetIf(SOCKET s)
{
    if (g_ifindex <= 0) return;
    DWORD idxNbo = htonl((DWORD)g_ifindex);
    setsockopt(s, IPPROTO_IP, IP_UNICAST_IF_OPTION,
               (const char *)&idxNbo, sizeof(idxNbo));
}

static void ForceBind(SOCKET s, int af)
{
    if (!g_ip[0] && g_ifindex <= 0) return;
    if (af == AF_INET) SetIf(s);   // IP_UNICAST_IF is IPv4-only
    if (!g_ip[0] || af != AF_INET) return;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    int len = sizeof(sin);
    int gr = getsockname(s, (struct sockaddr *)&sin, &len);
    int ge = WSAGetLastError();
    // On Windows getsockname() on an UNBOUND socket fails with WSAEINVAL.
    bool unbound = (gr != 0) ? (ge == WSAEINVAL)
                             : (sin.sin_family == AF_INET &&
                                sin.sin_addr.s_addr == INADDR_ANY && sin.sin_port == 0);
    if (unbound) {
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(g_ip);
        int br = bind(s, (struct sockaddr *)&sin, sizeof(sin));
        Dbg("bind socket=%llu ip=%s r=%d err=%d",
            (unsigned long long)s, g_ip, br, WSAGetLastError());
    }
}

// ---------------------------------------------------------------- replacements
static SOCKET WSAAPI My_socket(int af, int type, int proto)
{
    SOCKET s = pfn_socket(af, type, proto);
    if (s != INVALID_SOCKET && af == AF_INET) SetIf(s);
    return s;
}
static SOCKET WSAAPI My_WSASocketA(int af, int type, int proto,
        LPWSAPROTOCOL_INFOA info, GROUP g, DWORD flags)
{
    SOCKET s = pfn_WSASocketA(af, type, proto, info, g, flags);
    if (s != INVALID_SOCKET && af == AF_INET) SetIf(s);
    return s;
}
static SOCKET WSAAPI My_WSASocketW(int af, int type, int proto,
        LPWSAPROTOCOL_INFOW info, GROUP g, DWORD flags)
{
    SOCKET s = pfn_WSASocketW(af, type, proto, info, g, flags);
    if (s != INVALID_SOCKET && af == AF_INET) SetIf(s);
    return s;
}
static int WSAAPI My_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    char peer[128] = { 0 }, local[128] = { 0 };
    ForceBind(s, name ? name->sa_family : AF_INET);
    int r = pfn_connect(s, name, namelen);
    int err = WSAGetLastError();
    Dbg("connect  peer=%s local=%s if=%d r=%d err=%d",
        AddrText(name, peer, sizeof(peer)), LocalText(s, local, sizeof(local)),
        g_ifindex, r, err);
    WSASetLastError(err);
    return r;
}
static int WSAAPI My_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
        LPWSABUF in, LPWSABUF out, LPQOS qos, LPQOS qos2)
{
    char peer[128] = { 0 }, local[128] = { 0 };
    ForceBind(s, name ? name->sa_family : AF_INET);
    int r = pfn_WSAConnect(s, name, namelen, in, out, qos, qos2);
    int err = WSAGetLastError();
    Dbg("WSAConnect peer=%s local=%s if=%d r=%d err=%d",
        AddrText(name, peer, sizeof(peer)), LocalText(s, local, sizeof(local)),
        g_ifindex, r, err);
    WSASetLastError(err);
    return r;
}
static int WSAAPI My_sendto(SOCKET s, const char *buf, int len, int flags,
        const struct sockaddr *to, int tolen)
{
    char peer[128] = { 0 }, local[128] = { 0 };
    ForceBind(s, to ? to->sa_family : AF_INET);
    int r = pfn_sendto(s, buf, len, flags, to, tolen);
    int err = WSAGetLastError();
    Dbg("sendto   peer=%s local=%s if=%d r=%d err=%d",
        AddrText(to, peer, sizeof(peer)), LocalText(s, local, sizeof(local)),
        g_ifindex, r, err);
    WSASetLastError(err);
    return r;
}
static int WSAAPI My_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent,
        DWORD flags, const struct sockaddr *to, int tolen,
        LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    char peer[128] = { 0 }, local[128] = { 0 };
    ForceBind(s, to ? to->sa_family : AF_INET);
    int r = pfn_WSASendTo(s, bufs, count, sent, flags, to, tolen, ov, cr);
    int err = WSAGetLastError();
    Dbg("WSASendTo peer=%s local=%s if=%d r=%d err=%d",
        AddrText(to, peer, sizeof(peer)), LocalText(s, local, sizeof(local)),
        g_ifindex, r, err);
    WSASetLastError(err);
    return r;
}
static BOOL WSAAPI My_ConnectEx(SOCKET s, const struct sockaddr *name, int namelen,
        LPVOID sendbuf, DWORD sendlen, LPDWORD sent, LPOVERLAPPED ov)
{
    char peer[128] = { 0 }, local[128] = { 0 };
    ForceBind(s, name ? name->sa_family : AF_INET);
    BOOL r = pfn_ConnectEx(s, name, namelen, sendbuf, sendlen, sent, ov);
    int err = WSAGetLastError();
    Dbg("ConnectEx peer=%s local=%s if=%d r=%d err=%d",
        AddrText(name, peer, sizeof(peer)), LocalText(s, local, sizeof(local)),
        g_ifindex, (int)r, err);
    WSASetLastError(err);
    return r;
}
static int WSAAPI My_WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD inlen,
        LPVOID out, DWORD outlen, LPDWORD ret, LPWSAOVERLAPPED ov,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    int r = pfn_WSAIoctl(s, code, in, inlen, out, outlen, ret, ov, cr);
    int err = WSAGetLastError();
    if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        in && inlen >= sizeof(GUID) && out && outlen >= sizeof(void *) &&
        IsEqualGUID(*(const GUID *)in, WSAID_CONNECTEX_LOCAL))
    {
        PFN_ConnectEx orig = *(PFN_ConnectEx *)out;
        if (orig && orig != My_ConnectEx) {
            pfn_ConnectEx = orig;
            *(PFN_ConnectEx *)out = My_ConnectEx;
            Dbg("hooked ConnectEx");
        }
    }
    WSASetLastError(err);
    return r;
}

// ------------------------------------------------ inject into a freshly spawned child
static bool InjectPid(DWORD pid, bool suspended)
{
    if (!g_dllpath[0]) return false;
    size_t len = strlen(g_dllpath) + 1;
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) { Dbg("inject OpenProcess(%u) failed %lu", pid, GetLastError()); return false; }
    LPVOID remote = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    bool ok = false;
    do {
        if (!remote) break;
        if (!WriteProcessMemory(h, remote, g_dllpath, len, NULL)) break;
        LPTHREAD_START_ROUTINE load = (LPTHREAD_START_ROUTINE)
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!load) break;
        HANDLE th = CreateRemoteThread(h, NULL, 0, load, remote, 0, NULL);
        if (!th) break;
        WaitForSingleObject(th, 10000);
        CloseHandle(th);
        ok = true;
    } while (0);
    if (remote) VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    CloseHandle(h);
    Dbg("inject pid=%u suspended=%d ok=%d", pid, (int)suspended, (int)ok);
    return ok;
}

static BOOL WINAPI My_CreateProcessW(LPCWSTR app, LPWSTR cmd,
        LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
        DWORD flags, LPVOID env, LPCWSTR dir,
        LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    bool callerSuspended = (flags & CREATE_SUSPENDED) != 0;
    DWORD callFlags = callerSuspended ? flags : (flags | CREATE_SUSPENDED);
    BOOL ok = pfn_CreateProcessW(app, cmd, pa, ta, inherit, callFlags, env, dir, si, pi);
    DWORD err = GetLastError();
    if (!ok) return FALSE;

    if (pi) {
        Dbg("CreateProcessW child=%u suspended=%d", pi->dwProcessId, (int)!callerSuspended);
        bool injected = InjectPid(pi->dwProcessId, !callerSuspended);
        if (!callerSuspended && pi->hThread) {
            DWORD rr = ResumeThread(pi->hThread);
            Dbg("resume child=%u r=%lu injected=%d", pi->dwProcessId, rr, (int)injected);
        }
    }
    SetLastError(err);
    return ok;
}
static BOOL WINAPI My_CreateProcessA(LPCSTR app, LPSTR cmd,
        LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
        DWORD flags, LPVOID env, LPCSTR dir,
        LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
    bool callerSuspended = (flags & CREATE_SUSPENDED) != 0;
    DWORD callFlags = callerSuspended ? flags : (flags | CREATE_SUSPENDED);
    BOOL ok = pfn_CreateProcessA(app, cmd, pa, ta, inherit, callFlags, env, dir, si, pi);
    DWORD err = GetLastError();
    if (!ok) return FALSE;

    if (pi) {
        Dbg("CreateProcessA child=%u suspended=%d", pi->dwProcessId, (int)!callerSuspended);
        bool injected = InjectPid(pi->dwProcessId, !callerSuspended);
        if (!callerSuspended && pi->hThread) {
            DWORD rr = ResumeThread(pi->hThread);
            Dbg("resume child=%u r=%lu injected=%d", pi->dwProcessId, rr, (int)injected);
        }
    }
    SetLastError(err);
    return ok;
}

// ---------------------------------------------------------------- IAT patch
static void PatchModule(HMODULE mod)
{
    if (!mod || mod == g_hModule) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return;

    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)mod + impRva);
    for (; desc && desc->Name; desc++) {
        const char *dllName = (const char *)((BYTE *)mod + desc->Name);
        PIMAGE_THUNK_DATA first = (PIMAGE_THUNK_DATA)((BYTE *)mod + desc->FirstThunk);
        for (int i = 0; first[i].u1.Function; i++) {
            ULONG_PTR cur = first[i].u1.Function;
            void *repl = NULL;
            const char *fn = "";
            if      (pfn_connect        && cur == (ULONG_PTR)pfn_connect)        { repl = (void *)My_connect;        fn = "connect"; }
            else if (pfn_WSAConnect     && cur == (ULONG_PTR)pfn_WSAConnect)     { repl = (void *)My_WSAConnect;     fn = "WSAConnect"; }
            else if (pfn_sendto         && cur == (ULONG_PTR)pfn_sendto)         { repl = (void *)My_sendto;         fn = "sendto"; }
            else if (pfn_socket         && cur == (ULONG_PTR)pfn_socket)         { repl = (void *)My_socket;         fn = "socket"; }
            else if (pfn_WSASocketA     && cur == (ULONG_PTR)pfn_WSASocketA)     { repl = (void *)My_WSASocketA;     fn = "WSASocketA"; }
            else if (pfn_WSASocketW     && cur == (ULONG_PTR)pfn_WSASocketW)     { repl = (void *)My_WSASocketW;     fn = "WSASocketW"; }
            else if (pfn_WSASendTo      && cur == (ULONG_PTR)pfn_WSASendTo)      { repl = (void *)My_WSASendTo;      fn = "WSASendTo"; }
            else if (pfn_WSAIoctl       && cur == (ULONG_PTR)pfn_WSAIoctl)       { repl = (void *)My_WSAIoctl;       fn = "WSAIoctl"; }
            else if (pfn_CreateProcessW && cur == (ULONG_PTR)pfn_CreateProcessW) { repl = (void *)My_CreateProcessW; fn = "CreateProcessW"; }
            else if (pfn_CreateProcessA && cur == (ULONG_PTR)pfn_CreateProcessA) { repl = (void *)My_CreateProcessA; fn = "CreateProcessA"; }
            if (!repl) continue;

            DWORD oldProt = 0;
            PVOID slot = &first[i].u1.Function;
            if (VirtualProtect(slot, sizeof(PVOID), PAGE_READWRITE, &oldProt)) {
                first[i].u1.Function = (ULONG_PTR)repl;
                VirtualProtect(slot, sizeof(PVOID), oldProt, &oldProt);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(PVOID));
                Dbg("hooked %-16s in %s", fn, dllName);
            }
        }
    }
}

static void ScanModules(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do { PatchModule(me.hModule); } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

static void InstallHooks(void)
{
    if (InterlockedExchange(&g_installed, 1) != 0) return;

    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!ws2 || !k32) {
        Dbg("core DLL not loaded yet (ws2=%d k32=%d)", (int)(ws2 != 0), (int)(k32 != 0));
        g_installed = 0;
        return;
    }

    pfn_connect        = (PFN_connect)       GetProcAddress(ws2, "connect");
    pfn_WSAConnect     = (PFN_WSAConnect)    GetProcAddress(ws2, "WSAConnect");
    pfn_sendto         = (PFN_sendto)        GetProcAddress(ws2, "sendto");
    pfn_socket         = (PFN_socket)        GetProcAddress(ws2, "socket");
    pfn_WSASocketA     = (PFN_WSASocketA)    GetProcAddress(ws2, "WSASocketA");
    pfn_WSASocketW     = (PFN_WSASocketW)    GetProcAddress(ws2, "WSASocketW");
    pfn_WSASendTo      = (PFN_WSASendTo)     GetProcAddress(ws2, "WSASendTo");
    pfn_WSAIoctl       = (PFN_WSAIoctl)      GetProcAddress(ws2, "WSAIoctl");
    pfn_CreateProcessW = (PFN_CreateProcessW)GetProcAddress(k32, "CreateProcessW");
    pfn_CreateProcessA = (PFN_CreateProcessA)GetProcAddress(k32, "CreateProcessA");
    if (!pfn_connect || !pfn_socket || !pfn_CreateProcessW) {
        Dbg("missing required exports");
        g_installed = 0;
        return;
    }

    ScanModules();
    Dbg("hooks installed (v3)");

    // Catch modules (and therefore their IATs) that appear after injection.
    if (InterlockedExchange(&g_maintStarted, 1) == 0) {
        HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(void *)MaintenanceThread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
}

// DllMain cannot safely create the maintenance thread before hooks exist, so the
// thread entry is declared after InstallHooks via a forward declaration below.
static DWORD WINAPI MaintenanceThread(LPVOID)
{
    for (;;) {
        Sleep(500);
        if (InterlockedCompareExchange(&g_installed, 0, 0) == 1) ScanModules();
    }
}

// If ws2_32 is not loaded yet in a brand new child, retry after DllMain returns
// (no loader lock held).
static DWORD WINAPI RetryThread(LPVOID)
{
    for (int i = 0; i < 500; i++) {
        Sleep(10);
        if (InterlockedCompareExchange(&g_installed, 0, 0) == 1) break;
        if (GetModuleHandleA("ws2_32.dll") && GetModuleHandleA("kernel32.dll")) {
            InstallHooks();
            break;
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (!g_logCsInit) { InitializeCriticalSection(&g_logCs); g_logCsInit = true; }
        DisableThreadLibraryCalls(hModule);
        LoadConfig();
        Dbg("attach (v3)");
        if (GetModuleHandleA("ws2_32.dll") && GetModuleHandleA("kernel32.dll")) {
            InstallHooks();
        } else {
            Dbg("core DLL pending - retry thread");
            HANDLE th = CreateThread(NULL, 0, RetryThread, NULL, 0, NULL);
            if (th) CloseHandle(th);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        Dbg("detach");
    }
    return TRUE;
}
