#include <windows.h>
#include <winifnc.h>
#include <ntdll.h>

FARPROC WINAPI GetProcAddress(HINSTANCE hModule, LPCSTR lpProcName)
{
    ANSI_STRING ProcedureName, *ProcNamePtr = nullptr;
    FARPROC fnExp = nullptr;
    NTSTATUS Status;
    PVOID hMapped;
    ULONG Ordinal = 0;

    if ((ULONG_PTR)lpProcName > MAXUSHORT)
    {
        RtlInitAnsiString(&ProcedureName, (LPSTR)lpProcName);
        ProcNamePtr = &ProcedureName;
    }
    else
    {
        Ordinal = PtrToUlong(lpProcName);
    }

    hMapped = BasepMapModuleHandle(hModule, false);

    Status = LdrGetProcedureAddress(hMapped, ProcNamePtr, Ordinal, (PVOID*)&fnExp);

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return nullptr;
    }

    if (fnExp == hMapped)
    {
        if (HIWORD(lpProcName) != 0)
            BaseSetLastNTError(STATUS_ENTRYPOINT_NOT_FOUND);
        else
            BaseSetLastNTError(STATUS_ORDINAL_NOT_FOUND);
 
        return nullptr;
    }
 
    return fnExp;
}

DWORD BaseSetLastNTError( _In_ NTSTATUS Status ) /* fuck conversions go use nt statuses */
{
    NtCurrentTeb()->LastErrorValue = Status;
    return Status;
}

PVOID WINAPI BasepMapModuleHandle(HMODULE hModule, BOOLEAN AsDataFile)
{
    if (!hModule) return NtCurrentPeb()->ImageBaseAddress;
 
    if (LDR_IS_DATAFILE(hModule) && !AsDataFile)
        return nullptr;
 
    return hModule;
}