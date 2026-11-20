// inject.exe <pid> <full\path\to\bindnic.dll>
// Loads bindnic.dll into the target process via CreateRemoteThread/LoadLibraryA.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: inject.exe <pid> <dll-full-path>\n");
        return 2;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char *dll = argv[2];

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess(%u) failed: %lu\n", pid, GetLastError());
        return 3;
    }

    size_t len = strlen(dll) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        fprintf(stderr, "VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 4;
    }
    if (!WriteProcessMemory(hProc, remote, dll, len, NULL)) {
        fprintf(stderr, "WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 5;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA");
    if (!loadLib) {
        fprintf(stderr, "GetProcAddress(LoadLibraryA) failed\n");
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 6;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loadLib, remote, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 7;
    }

    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    printf("injected into %u\n", pid);
    return 0;
}
