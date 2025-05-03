#include <bootstrap/core.h>
#include <bootstrap/bytepattern.h>
#include <bootstrap/syscalltable.h>
#include <hash/ntdll.h>
#include <hash/util.h>
#include <windows.h>
#include <winifnc.h>
#include <stdarg.h>
#include <dbgio.h>

PLDR_DATA_TABLE_ENTRY FindInMemoryModuleByHash(unsigned long long target_hash) {
    PPEB pPeb = NtCurrentPeb();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead)
    {
        PLDR_DATA_TABLE_ENTRY pEntry =
            CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (fnv1aWideHash(pEntry->BaseDllName.Buffer) == target_hash)
        {
            return pEntry;
            break;
        }
        pListEntry = pListEntry->Flink;
    }
    return nullptr;
}

PVOID FindExportByHash(PLDR_DATA_TABLE_ENTRY module, unsigned long long target_hash) {
    if (!module)
        return nullptr;

    PVOID module_base = module->DllBase;
    if (!module_base)
        return nullptr;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    IMAGE_DATA_DIRECTORY export_dir_data = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_data.Size == 0 || export_dir_data.VirtualAddress == 0)
        return nullptr;

    PIMAGE_EXPORT_DIRECTORY export_dir =
        (PIMAGE_EXPORT_DIRECTORY)(module_base + export_dir_data.VirtualAddress);
    if (!export_dir)
        return nullptr;

    const UINT* names = (const UINT*)(module_base + export_dir->AddressOfNames);
    const USHORT* ordinals = (const USHORT*)(module_base + export_dir->AddressOfNameOrdinals);
    const UINT* functions = (const UINT*)(module_base + export_dir->AddressOfFunctions);
    if (!names || !ordinals || !functions)
        return nullptr;

    for (size_t i = 0; i < export_dir->NumberOfNames; ++i)
    {
        const char* func_name = (const char*)(module_base + names[i]);
        if (!func_name)
            continue;

        if (fnv1aHash(func_name) == target_hash)
        {
            USHORT ordinal = ordinals[i];
            if (ordinal >= export_dir->NumberOfFunctions)
                return nullptr;

            PVOID function_address = module_base + functions[ordinal];
            return function_address;
        }
    }
    return nullptr;
}

int ExtractSyscallFromNativeStub(PVOID function) {
    const BYTE* bytes = (const BYTE*)function;

    BOOL matched = BYTEPATTERN_MATCH(
        bytes,
        0x4C, 0x8B, 0xD1,                               // mov r10, rcx
        0xB8, 0x100, 0x100, 0x100, 0x100                // mov eax, imm32
    );

    if (!matched)
        return -1;
    
    return *(const int*)(bytes + 4);
}

SyscallEntry g_SyscallTable[SYSCALL_TABLE_MAX] = {0};
int g_SyscallCount = 0;

int ResolveSyscallTable(PLDR_DATA_TABLE_ENTRY ntdll) {
    static const ULONGLONG g_SyscallHashList[] = {
        NtAllocateVirtualMemory_HASH,
        NtFreeVirtualMemory_HASH,
        NtProtectVirtualMemory_HASH,
        NtReadVirtualMemory_HASH,
        NtWriteVirtualMemory_HASH,
        NtCreateFile_HASH,
        NtOpenFile_HASH,
        NtReadFile_HASH,
        NtWriteFile_HASH,
        NtClose_HASH,
        NtQueryInformationFile_HASH,
        NtCreateProcessEx_HASH,
        NtCreateThreadEx_HASH,
        NtQueryInformationProcess_HASH,
        NtOpenProcess_HASH,
        NtOpenThread_HASH,
        NtTerminateProcess_HASH,
        NtDelayExecution_HASH,
        NtQueryPerformanceCounter_HASH,
        NtYieldExecution_HASH,
        NtQuerySystemInformation_HASH,
        NtGetContextThread_HASH,
        NtSetContextThread_HASH,
        NtResumeThread_HASH,
        NtSuspendThread_HASH,
        NtMapViewOfSection_HASH,
        NtUnmapViewOfSection_HASH,
        NtCreateSection_HASH,
        NtQueryObject_HASH,
        NtDuplicateObject_HASH,
        NtOpenProcessTokenEx_HASH,
        NtOpenThreadTokenEx_HASH,
        NtAdjustPrivilegesToken_HASH,
        NtSetInformationToken_HASH,
        NtCreateKey_HASH,
        NtOpenKey_HASH,
        NtDeleteKey_HASH,
        NtSetValueKey_HASH,
        NtQueryValueKey_HASH,
        NtEnumerateKey_HASH,
        NtEnumerateValueKey_HASH,
        NtCreateDirectoryObject_HASH,
        NtOpenDirectoryObject_HASH,
        NtQueryDirectoryObject_HASH,
        NtCreateSymbolicLinkObject_HAS,
        NtOpenSymbolicLinkObject_HAS,
        NtCreateEvent_HASH,
        NtSetEvent_HASH,
        NtClearEvent_HASH,
        NtWaitForSingleObject_HASH,
        NtQueryInformationToken_HASH
    };

    for (int i = 0; i < sizeof(g_SyscallHashList) / sizeof(g_SyscallHashList[0]); ++i) {
        uint64_t hash = g_SyscallHashList[i];
        void *func = FindExportByHash(ntdll, hash);
        if (!func)
            return -1;

        int syscall_number = ExtractSyscallFromNativeStub(func);
        if (syscall_number < 0)
            return -2;

        g_SyscallTable[g_SyscallCount++] = (SyscallEntry){
            .hash = hash,
            .syscall_number = (uint32_t)syscall_number
        };

        if (g_SyscallCount >= SYSCALL_TABLE_MAX)
            return -3;
    }
    
    return 0;
}

