#ifndef NTDLL_H
#define NTDLL_H

#include <windows.h>

typedef struct _ROS_APISET
{
    const UNICODE_STRING Name;
    const UNICODE_STRING Target;
    DWORD dwOsVersions;
} ROS_APISET;
 
extern const ROS_APISET g_Apisets[];
extern const LONG g_ApisetsCount;

typedef NTSTATUS (NTAPI* ZwRaiseException_t )(_In_ PEXCEPTION_RECORD ExceptionRecord, _In_ PCONTEXT Context, _In_ BOOLEAN SearchFrames);
extern ZwRaiseException_t ZwRaiseException;
typedef BOOLEAN (NTAPI* RtlCallVectoredExceptionHandlers_t)(_In_ PEXCEPTION_RECORD ExceptionRecord, _In_ PCONTEXT Context );
extern RtlCallVectoredExceptionHandlers_t RtlCallVectoredExceptionHandlers;
typedef BOOLEAN (NTAPI* RtlCallVectoredContinueHandlers_t)(_In_ PEXCEPTION_RECORD ExceptionRecord, _In_ PCONTEXT Context );
extern RtlCallVectoredContinueHandlers_t RtlCallVectoredContinueHandlers;
typedef BOOLEAN (NTAPI* RtlpUnwindInternal_t)(_In_ PVOID TargetFrame, _In_ PVOID TargetIp, _In_ PEXCEPTION_RECORD ExceptionRecord, _In_ PVOID ReturnValue, _In_ PCONTEXT ContextRecord, _In_opt_ struct _UNWIND_HISTORY_TABLE* HistoryTable, _In_ ULONG HandlerType );
extern RtlpUnwindInternal_t RtlpUnwindInternal;
typedef VOID (NTAPI* RtlCaptureContext_t)(_Out_ PCONTEXT ContextRecord);
extern RtlCaptureContext_t RtlCaptureContext;
typedef NTSTATUS (NTAPI* NtRaiseHardError_t)(_In_ NTSTATUS ErrorStatus, _In_ ULONG NumberOfParameters, _In_ ULONG UnicodeStringParameterMask, _In_ PULONG_PTR Parameters, _In_ ULONG ValidResponseOptions, _Out_ PULONG Response );
extern NtRaiseHardError_t NtRaiseHardError;
typedef NTSTATUS (NTAPI* LdrOpenImageFileOptionsKey_t)(_In_ PUNICODE_STRING SubKey, _In_ BOOLEAN Wow64, _Out_ PHANDLE NewKeyHandle);
extern LdrOpenImageFileOptionsKey_t LdrOpenImageFileOptionsKey;
typedef NTSTATUS (NTAPI* LdrQueryImageFileKeyOption_t)(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName, _In_ ULONG Type, _Out_ PVOID Buffer, _In_ ULONG BufferSize, _Out_ PULONG ReturnedLength);
extern LdrQueryImageFileKeyOption_t LdrQueryImageFileKeyOption;
typedef NTSTATUS (NTAPI* NtClose_t)(_In_ HANDLE Handle);
extern NtClose_t NtClose;
typedef NTSTATUS (NTAPI* LdrpRunInitializeRoutines_t)(_In_ PCONTEXT Context);
extern LdrpRunInitializeRoutines_t LdrpRunInitializeRoutines;
typedef NTSTATUS (NTAPI* RtlDosSearchPath_U_t)(_In_ PCWSTR Path, _In_ PCWSTR FileName, _In_ PCWSTR Extension, _In_ ULONG Size, _In_ PWSTR Buffer, _Out_ PWSTR* PartName);
extern RtlDosSearchPath_U_t RtlDosSearchPath_U;
typedef BOOLEAN (NTAPI* RtlDosPathNameToNtPathName_U_t)(_In_ PCWSTR DosFileName, _Out_ PUNICODE_STRING NtFileName, _Out_ PCWSTR *FilePart, _Out_ PRTL_RELATIVE_NAME_U RelativeName);
extern RtlDosPathNameToNtPathName_U_t RtlDosPathNameToNtPathName_U;
typedef NTSTATUS (NTAPI* NtOpenFile_t)(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG ShareMode, _In_ ULONG OpenOptions);
extern NtOpenFile_t NtOpenFile;
typedef NTSTATUS (NTAPI* NtCreateSection_t)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG Protection, _In_ ULONG Attributes, _In_opt_ HANDLE FileHandle);
extern NtCreateSection_t NtCreateSection;
typedef NTSTATUS (NTAPI* NtMapViewOfSection_t)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize, _Inout_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize, _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG PageProtection);
extern NtMapViewOfSection_t NtMapViewOfSection;
typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress);
extern NtUnmapViewOfSection_t NtUnmapViewOfSection;
typedef NTSTATUS (NTAPI* NtAreMappedFilesTheSame_t)(_In_ PVOID File1Base, _In_ PVOID File2Base);
extern NtAreMappedFilesTheSame_t NtAreMappedFilesTheSame;
typedef NTSTATUS (NTAPI* NtOpenSection_t)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes);
extern NtOpenSection_t NtOpenSection;

NTSTATUS NTAPI LdrpGetProcedureAddress(_In_ PVOID BaseAddress, _In_opt_ PANSI_STRING Name, _In_opt_ ULONG Ordinal, _Out_ PVOID* ProcedureAddress, BOOLEAN ExecuteInit);
NTSTATUS NTAPI LdrGetProcedureAddress(_In_ PVOID BaseAddress, _In_opt_ PANSI_STRING Name, _In_opt_ ULONG Ordinal, _Out_ PVOID* ProcedureAddress);

#endif //NTDLL_H