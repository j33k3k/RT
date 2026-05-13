.intel_syntax noprefix
.global SysNtOpenProcess
.global SysNtAllocateVirtualMemory
.global SysNtWriteVirtualMemory
.global SysNtCreateThreadEx
.global SysNtProtectVirtualMemory

SysNtOpenProcess:
    mov r10, rcx
    mov eax, 0x0026
    syscall
    ret

SysNtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x0018
    syscall
    ret

SysNtWriteVirtualMemory:
    mov r10, rcx
    mov eax, 0x003A
    syscall
    ret

SysNtCreateThreadEx:
    mov r10, rcx
    mov eax, 0x00C9
    syscall
    ret

SysNtProtectVirtualMemory:
    mov r10, rcx
    mov eax, 0x0050
    syscall
    ret
