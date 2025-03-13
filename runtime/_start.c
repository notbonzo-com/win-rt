#include <windows.h>
#include <ntdll.h>
#include <hash/ntdll.h>
#include <bootstrap/core.h>

extern int main(int argc, char **argv);
void __resolve_needed();

/* this function returns into ntdll!RtlUserThreadStart */
/* at this point we have a 1MiB stack and a 1MiB heap managed by __bootstrap_alloc */
int _start() {
    __resolve_needed();

    int status = main(0, nullptr);

    return status; /* You can return into RtlUserThreadStart */
}

ZwRaiseException_t ZwRaiseException;
RtlCallVectoredExceptionHandlers_t RtlCallVectoredExceptionHandlers;
RtlCallVectoredContinueHandlers_t RtlCallVectoredContinueHandlers;
RtlpUnwindInternal_t RtlpUnwindInternal;
RtlCaptureContext_t RtlCaptureContext;
NtRaiseHardError_t NtRaiseHardError;
LdrOpenImageFileOptionsKey_t LdrOpenImageFileOptionsKey;
LdrQueryImageFileKeyOption_t LdrQueryImageFileKeyOption;
NtClose_t NtClose;
LdrpRunInitializeRoutines_t LdrpRunInitializeRoutines;
RtlDosSearchPath_U_t RtlDosSearchPath_U;
RtlDosPathNameToNtPathName_U_t RtlDosPathNameToNtPathName_U;
NtOpenFile_t NtOpenFile;
NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtUnmapViewOfSection_t NtUnmapViewOfSection;
NtAreMappedFilesTheSame_t NtAreMappedFilesTheSame;
NtOpenSection_t NtOpenSection;

void __resolve_needed()
{
    PLDR_DATA_TABLE_ENTRY ntdll_module = __bootstrap_find_module(NTDLL_HASH);

    ZwRaiseException = (ZwRaiseException_t)__bootstrap_get_export(ntdll_module, ZwRaiseException_HASH);
    RtlCallVectoredExceptionHandlers = (RtlCallVectoredExceptionHandlers_t)__bootstrap_get_export(ntdll_module, RtlCallVectoredExceptionHandlers_HASH);
    RtlCallVectoredContinueHandlers = (RtlCallVectoredContinueHandlers_t)__bootstrap_get_export(ntdll_module, RtlCallVectoredContinueHandlers_HASH);
    RtlpUnwindInternal = (RtlpUnwindInternal_t)__bootstrap_get_export(ntdll_module, RtlpUnwindInternal_HASH);
    RtlCaptureContext = (RtlCaptureContext_t)__bootstrap_get_export(ntdll_module, RtlCaptureContext_HASH);
    NtRaiseHardError = (NtRaiseHardError_t)__bootstrap_get_export(ntdll_module, NtRaiseHardError_HASH);
    LdrOpenImageFileOptionsKey = (LdrOpenImageFileOptionsKey_t)__bootstrap_get_export(ntdll_module, LdrOpenImageFileOptionsKey_HASH);
    LdrQueryImageFileKeyOption = (LdrQueryImageFileKeyOption_t)__bootstrap_get_export(ntdll_module, LdrQueryImageFileKeyOption_HASH);
    NtClose = (NtClose_t)__bootstrap_get_export(ntdll_module, NtClose_HASH);
    LdrpRunInitializeRoutines = (LdrpRunInitializeRoutines_t)__bootstrap_get_export(ntdll_module, LdrpRunInitializeRoutines_HASH);
    RtlDosSearchPath_U = (RtlDosSearchPath_U_t)__bootstrap_get_export(ntdll_module, RtlDosSearchPath_U_HASH);
    RtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U_t)__bootstrap_get_export(ntdll_module, RtlDosPathNameToNtPathName_U_HASH);
    NtOpenFile = (NtOpenFile_t)__bootstrap_get_export(ntdll_module, NtOpenFile_HASH);
    NtCreateSection = (NtCreateSection_t)__bootstrap_get_export(ntdll_module, NtCreateSection_HASH);
    NtMapViewOfSection = (NtMapViewOfSection_t)__bootstrap_get_export(ntdll_module, NtMapViewOfSection_HASH);
    NtUnmapViewOfSection = (NtUnmapViewOfSection_t)__bootstrap_get_export(ntdll_module, NtUnmapViewOfSection_HASH);
    NtAreMappedFilesTheSame = (NtAreMappedFilesTheSame_t)__bootstrap_get_export(ntdll_module, NtAreMappedFilesTheSame_HASH);
    NtOpenSection = (NtOpenSection_t)__bootstrap_get_export(ntdll_module, NtOpenSection_HASH);
}