#include <bootstrap/core.h>
#include <windows.h>
#include <winfnc.h>

PLDR_DATA_TABLE_ENTRY __bootstrap_find_module(unsigned long long target_hash) {
    PPEB pPeb = NtCurrentPeb();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead)
    {
        PLDR_DATA_TABLE_ENTRY pEntry =
            CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (__bootstrap_fnv1a_whash(pEntry->BaseDllName.Buffer) == target_hash)
        {
            return pEntry;
            break;
        }
        pListEntry = pListEntry->Flink;
    }
    return nullptr;
}

PVOID __bootstrap_get_export(PLDR_DATA_TABLE_ENTRY module, unsigned long long target_hash) {
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

        if (__bootstrap_fnv1a_hash(func_name) == target_hash)
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