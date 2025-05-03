section .data

extern g_SyscallTable
extern g_GuiSyscallTable

section .text

%macro NT_SYSCALL_STUB 2
    global %1
    %1:
        mov     r10, rcx
        mov     eax, dword [rel g_SyscallTable + %2*16 + 8]
        syscall
        ret
%endmacro

NT_SYSCALL_STUB NtAllocateVirtualMemory,         0
NT_SYSCALL_STUB NtFreeVirtualMemory,             1
NT_SYSCALL_STUB NtProtectVirtualMemory,          2
NT_SYSCALL_STUB NtReadVirtualMemory,             3
NT_SYSCALL_STUB NtWriteVirtualMemory,            4
NT_SYSCALL_STUB NtCreateFile,                    5
NT_SYSCALL_STUB NtOpenFile,                      6
NT_SYSCALL_STUB NtReadFile,                      7
NT_SYSCALL_STUB NtWriteFile,                     8
NT_SYSCALL_STUB NtClose,                         9
NT_SYSCALL_STUB NtQueryInformationFile,         10
NT_SYSCALL_STUB NtCreateProcessEx,              11
NT_SYSCALL_STUB NtCreateThreadEx,               12
NT_SYSCALL_STUB NtQueryInformationProcess,      13
NT_SYSCALL_STUB NtOpenProcess,                  14
NT_SYSCALL_STUB NtOpenThread,                   15
NT_SYSCALL_STUB NtTerminateProcess,             16
NT_SYSCALL_STUB NtDelayExecution,               17
NT_SYSCALL_STUB NtQueryPerformanceCounter,      18
NT_SYSCALL_STUB NtYieldExecution,               19
NT_SYSCALL_STUB NtQuerySystemInformation,       20
NT_SYSCALL_STUB NtGetContextThread,             21
NT_SYSCALL_STUB NtSetContextThread,             22
NT_SYSCALL_STUB NtResumeThread,                 23
NT_SYSCALL_STUB NtSuspendThread,                24
NT_SYSCALL_STUB NtMapViewOfSection,             25
NT_SYSCALL_STUB NtUnmapViewOfSection,           26
NT_SYSCALL_STUB NtCreateSection,                27
NT_SYSCALL_STUB NtQueryObject,                  28
NT_SYSCALL_STUB NtDuplicateObject,              29
NT_SYSCALL_STUB NtOpenProcessTokenEx,           30
NT_SYSCALL_STUB NtOpenThreadTokenEx,            31
NT_SYSCALL_STUB NtAdjustPrivilegesToken,        32
NT_SYSCALL_STUB NtSetInformationToken,          33
NT_SYSCALL_STUB NtCreateKey,                    34
NT_SYSCALL_STUB NtOpenKey,                      35
NT_SYSCALL_STUB NtDeleteKey,                    36
NT_SYSCALL_STUB NtSetValueKey,                  37
NT_SYSCALL_STUB NtQueryValueKey,                38
NT_SYSCALL_STUB NtEnumerateKey,                 39
NT_SYSCALL_STUB NtEnumerateValueKey,            40
NT_SYSCALL_STUB NtCreateDirectoryObject,        41
NT_SYSCALL_STUB NtOpenDirectoryObject,          42
NT_SYSCALL_STUB NtQueryDirectoryObject,         43
NT_SYSCALL_STUB NtCreateSymbolicLinkObject,     44
NT_SYSCALL_STUB NtOpenSymbolicLinkObject,       45
NT_SYSCALL_STUB NtCreateEvent,                  46
NT_SYSCALL_STUB NtSetEvent,                     47
NT_SYSCALL_STUB NtClearEvent,                   48
NT_SYSCALL_STUB NtWaitForSingleObject,          49
NT_SYSCALL_STUB NtQueryInformationToken,        50
