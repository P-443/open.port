// bindnic.dll - force every NEW outbound Winsock socket in the host process
// to leave through one physical NIC (source IP + IP_UNICAST_IF).
// Injected into sshd.exe so its SOCKS/direct-tcpip sockets cannot re-enter
// a TUN/VPN default route and create a recursive loop.
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define IP_UNICAST_IF_OPTION 31   // IPPROTO_IP, DWORD index in NETWORK byte order

static char  g_ip[64]   = { 0 };
static int   g_ifindex  = 0;
static LONG  g_installed = 0;

#define BINDNIC_DEBUG 0
#if BINDNIC_DEBUG
static void Dbg(const char *s)
{
    HMODULE me = NULL;
    char path[MAX_PATH] = { 0 }, log[MAX_PATH] = { 0 };
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&Dbg, &me) && GetModuleFileNameA(me, path, MAX_PATH)) {
        strncpy_s(log, MAX_PATH, path, _TRUNCATE);
        char *slash = strrchr(log, '\\');
        if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - log), "bindnic-debug.log");
        FILE *f = NULL;
        if (fopen_s(&f, log, "a") == 0 && f) { fprintf(f, "%s\n", s); fclose(f); }
    }
}
#else
#define Dbg(s) ((void)0)
#endif

typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int,
                                     LPWSABUF, LPWSABUF, LPQOS, LPQOS);
static PFN_connect    pfn_connect    = NULL;
static PFN_WSAConnect pfn_WSAConnect = NULL;

// ---------------------------------------------------------------- config
static void LoadConfig(void)
{
    HMODULE me = NULL;
    char path[MAX_PATH] = { 0 }, cfg[MAX_PATH] = { 0 };
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)&LoadConfig, &me)) return;
    if (!GetModuleFileNameA(me, path, MAX_PATH)) return;

    strncpy_s(cfg, MAX_PATH, path, _TRUNCATE);
    char *slash = strrchr(cfg, '\\');
    if (slash) strcpy_s(slash + 1, MAX_PATH - (slash + 1 - cfg), "bindnic.cfg");
    else return;

    FILE *f = NULL;
    if (fopen_s(&f, cfg, "r") != 0 || !f) return;

    char line[128] = { 0 };
    if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0]) strncpy_s(g_ip, sizeof(g_ip), line, _TRUNCATE);
    }
    line[0] = 0;
    if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        g_ifindex = atoi(line);
    }
    fclose(f);
    { char b[160]; _snprintf_s(b, sizeof(b), _TRUNCATE, "config ip=%s if=%d", g_ip, g_ifindex); Dbg(b); }
}

// ---------------------------------------------------------------- force bind
static void ForceBind(SOCKET s)
{
    Dbg("ForceBind called");
    if (!g_ip[0] && g_ifindex <= 0) return;

    // Pin the outgoing interface by INDEX. This beats any 0.0.0.0/1 route a
    // TUN client installs. Winsock expects the index in network byte order.
    if (g_ifindex > 0) {
        DWORD idxNbo = htonl((DWORD)g_ifindex);
        int r = setsockopt(s, IPPROTO_IP, IP_UNICAST_IF_OPTION,
                           (const char *)&idxNbo, sizeof(idxNbo));
        { char b[200]; _snprintf_s(b, sizeof(b), _TRUNCATE, "  setsockopt IF r=%d err=%d", r, WSAGetLastError()); Dbg(b); }
    }

    // Bind the source address as well. Only touch sockets that are still
    // unbound (0.0.0.0:0) - accepted/listening sockets must not be changed.
    if (g_ip[0]) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        int len = sizeof(sin);
        int gr = getsockname(s, (struct sockaddr *)&sin, &len);
        int ge = WSAGetLastError();
        // On Windows getsockname() on a NOT-yet-bound socket fails with
        // WSAEINVAL - it does not return 0.0.0.0:0 like other platforms.
        bool unbound = (gr != 0) ? (ge == WSAEINVAL)
                                 : (sin.sin_family == AF_INET &&
                                    sin.sin_addr.s_addr == INADDR_ANY && sin.sin_port == 0);
        { char b[220]; _snprintf_s(b, sizeof(b), _TRUNCATE, "  getsockname r=%d err=%d unbound=%d", gr, ge, (int)unbound); Dbg(b); }
        if (unbound) {
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = inet_addr(g_ip);
            sin.sin_port = 0;
            int br = bind(s, (struct sockaddr *)&sin, sizeof(sin));
            { char b[200]; _snprintf_s(b, sizeof(b), _TRUNCATE, "  bind r=%d err=%d want=%08x", br, WSAGetLastError(), sin.sin_addr.s_addr); Dbg(b); }
        }
    }
}

static int WSAAPI My_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    ForceBind(s);
    return pfn_connect(s, name, namelen);
}

static int WSAAPI My_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
                                LPWSABUF in, LPWSABUF out, LPQOS qos, LPQOS qos2)
{
    ForceBind(s);
    return pfn_WSAConnect(s, name, namelen, in, out, qos, qos2);
}

// ---------------------------------------------------------------- IAT patch
static void PatchModule(HMODULE mod)
{
    char mn[MAX_PATH] = { 0 };
    GetModuleFileNameA(mod, mn, MAX_PATH);
    { char b[MAX_PATH + 32]; _snprintf_s(b, sizeof(b), _TRUNCATE, "PatchModule: %s", mn); Dbg(b); }
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) { Dbg("PatchModule: no import dir"); return; }

    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)mod + impRva);
    for (; desc && desc->Name; desc++) {
        const char *dllName = (const char *)((BYTE *)mod + desc->Name);
        { char b[260]; _snprintf_s(b, sizeof(b), _TRUNCATE, "  import: %s", dllName); Dbg(b); }
        if (_stricmp(dllName, "ws2_32.dll") != 0 &&
            _stricmp(dllName, "ws2_32") != 0) continue;
        { char b[260]; _snprintf_s(b, sizeof(b), _TRUNCATE, "  ws2 desc OFT=%08x FT=%08x", desc->OriginalFirstThunk, desc->FirstThunk); Dbg(b); }

        // MSVC links ws2_32 imports BY ORDINAL (e.g. 0x8000...), so walking
        // OriginalFirstThunk by NAME misses connect entirely.  The FirstThunk
        // (IAT) slots are already resolved to the real function pointers at
        // load time, so match those against connect/WSAConnect directly.
        PIMAGE_THUNK_DATA first = (PIMAGE_THUNK_DATA)((BYTE *)mod + desc->FirstThunk);
        for (int i = 0; first[i].u1.Function; i++) {
            ULONG_PTR cur = first[i].u1.Function;
            void *replacement = NULL;
            const char *fname = "";
            if (cur == (ULONG_PTR)pfn_connect) {
                replacement = (void *)My_connect; fname = "connect";
            } else if (pfn_WSAConnect && cur == (ULONG_PTR)pfn_WSAConnect) {
                replacement = (void *)My_WSAConnect; fname = "WSAConnect";
            }
            if (!replacement) continue;

            DWORD oldProt = 0;
            PVOID slot = &first[i].u1.Function;
            if (VirtualProtect(slot, sizeof(PVOID), PAGE_READWRITE, &oldProt)) {
                first[i].u1.Function = (ULONG_PTR)replacement;
                VirtualProtect(slot, sizeof(PVOID), oldProt, &oldProt);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(PVOID));
                { char b[260]; _snprintf_s(b, sizeof(b), _TRUNCATE, "patched %s in module %s", fname, mn); Dbg(b); }
            }
        }
    }
}

static void InstallHooks(void)
{
    if (InterlockedExchange(&g_installed, 1) != 0) return;

    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) { Dbg("InstallHooks: no ws2_32"); return; }
    pfn_connect    = (PFN_connect)GetProcAddress(ws2, "connect");
    pfn_WSAConnect = (PFN_WSAConnect)GetProcAddress(ws2, "WSAConnect");
    if (!pfn_connect) { Dbg("InstallHooks: no connect"); return; }
    Dbg("InstallHooks: ws2 ok");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap == INVALID_HANDLE_VALUE) { Dbg("InstallHooks: snapshot failed"); return; }
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do { PatchModule(me.hModule); } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        LoadConfig();
        // Defer hooking until DllMain returns (loader lock): a tiny thread is
        // safer, but sshd creates sockets after startup, so doing it here is
        // sufficient and avoids a race with the first forwarded connection.
        InstallHooks();
    }
    return TRUE;
}
