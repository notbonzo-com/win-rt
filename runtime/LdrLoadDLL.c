#include <bootstrap/core.h>
#include <windows.h>
#include <winfnc.h>

UNICODE_STRING LdrApiDefaultExtension = {
    sizeof(L".dll"),
    sizeof(L".dll"),
    L".dll"
};

NTSTATUS NTAPI LdrpMapDll( _In_ PWSTR SearchPath, _In_ PWSTR DllPath2, _In_ PWSTR DllName, _In_ PULONG DllCharacteristics, _In_ BOOLEAN Static, _In_ BOOLEAN Redirect, _Out_ PLDR_DATA_TABLE_ENTRY* DataTableEntry )
{

}

NTSTATUS NTAPI LdrpCheckForLoadedDll( _In_ PWSTR DllPath, _In_ PUNICODE_STRING DllName, _In_ BOOLEAN Flag, _In_ BOOLEAN RedirectDLL, _Out_ PLDR_DATA_TABLE_ENTRY* LdrEntry )
{

}

NTSTATUS NTAPI LdrpLoadDll(_In_ BOOLEAN Redirected, _In_ PWSTR DllPath, _In_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* BaseAddress, _In_ BOOLEAN CallInit )
{
    PPEB Peb = NtCurrentPeb();
    NTSTATUS Status = 0;
    const WCHAR *p;
    BOOLEAN GotExtension;
    WCHAR c;
    WCHAR NameBuffer[MAX_PATH + 6];
    UNICODE_STRING RawDllName;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    // BOOLEAN InInit = LdrpInLdrInit;
 
    if (DllName->Length >= sizeof(NameBuffer)) return STATUS_NAME_TOO_LONG;
    RtlInitEmptyUnicodeString(&RawDllName, NameBuffer, sizeof(NameBuffer));
    RtlCopyUnicodeString(&RawDllName, DllName);

    p = DllName->Buffer + DllName->Length / sizeof(WCHAR) - 1;
    GotExtension = false;
    while (p >= DllName->Buffer)
    {
        c = *p--;
        if (c == L'.')
        {
            GotExtension = true;
            break;
        }
        else if (c == L'\\')
        {
            break;
        }
    }

    if (!GotExtension)
    {
        if ((DllName->Length + LdrApiDefaultExtension.Length + sizeof(UNICODE_NULL)) >=
            sizeof(NameBuffer))
        {
            return STATUS_NAME_TOO_LONG;
        }
 
        (VOID)RtlAppendUnicodeStringToString(&RawDllName, &LdrApiDefaultExtension);
    }

    __try {
        if (!LdrpCheckForLoadedDll(DllPath, &RawDllName, false, Redirected, &LdrEntry)) {
            Status = LdrpMapDll(DllPath, DllPath, NameBuffer, DllCharacteristics, false, Redirected, &LdrEntry);
            if (!NT_SUCCESS(Status)) {
                __leave;
            }
            if ((DllCharacteristics) && (*DllCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
            {
                LdrEntry->EntryPoint = nullptr;
                LdrEntry->Flags &= ~0x4;
            }
            /* todo continue */
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

PUNICODE_STRING LdrpTopLevelDllBeingLoaded;

NTSTATUS NTAPI LoadDLL(_In_ PUNICODE_STRING DllName, _Out_ PVOID* BaseAddress)
{
    NTSTATUS Status;
    PUNICODE_STRING OldTldDll;

    OldTldDll = LdrpTopLevelDllBeingLoaded;

    __try {
        LdrpTopLevelDllBeingLoaded = DllName;

        Status = LdrpLoadDll(false,
                            nullptr,
                            nullptr,
                            DllName,
                            BaseAddress,
                            true);

        if (NT_SUCCESS(Status)) {
            Status = 0;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    LdrpTopLevelDllBeingLoaded = OldTldDll;
    return Status;
}

