// Run this first to get SSNs for your build
#include <Windows.h>
#include <stdio.h>

WORD GetSSN(const char* funcName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PBYTE funcAddr = (PBYTE)GetProcAddress(ntdll, funcName);
    if (!funcAddr) return 0;

    // Clean stub pattern:
    // 4C 8B D1    mov r10, rcx
    // B8 XX 00    mov eax, SSN
    if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B &&
        funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8) {
        return *(WORD*)(funcAddr + 4);
    }
    return 0;
}

int main() {
    const char* funcs[] = {
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtProtectVirtualMemory"
    };
    for (auto f : funcs) {
        wprintf(L"%-40S SSN = 0x%04X\n", f, GetSSN(f));
    }
    return 0;
}
