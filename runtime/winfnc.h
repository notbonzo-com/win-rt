#ifndef WINFNC_H
#define WINFNC_H

#include <windows.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef NTSTATUS(NTAPI* NtWriteFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    _In_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_ HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* ZwMapViewOfSection_t)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _In_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* RtlAllocateHeap_t)(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ SIZE_T Size
);

typedef NTSTATUS(NTAPI* RtlFreeHeap_t)(
    _In_ HANDLE HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress
);

typedef NTSTATUS(NTAPI* RtlCreateEnvironment_t)(
    _In_ BOOLEAN CloneCurrentEnvironment,
    _Out_ PVOID *Environment
);

typedef NTSTATUS(NTAPI* RtlDestroyEnvironment_t)(
    _In_ PVOID Environment
);

typedef NTSTATUS(NTAPI* RtlSetEnvironmentVariable_t)(
    _Inout_ PVOID *Environment,
    _In_ PUNICODE_STRING Name,
    _In_opt_ PUNICODE_STRING Value
);

typedef NTSTATUS(NTAPI* RtlQueryEnvironmentVariable_U_t)(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Name,
    _Inout_ PUNICODE_STRING Value
);

typedef NTSTATUS(NTAPI* RtlInitializeCriticalSection_t)(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection
);

typedef NTSTATUS(NTAPI* RtlEncodePointer_t)(
    _In_ PVOID Ptr
);

typedef NTSTATUS(NTAPI* RtlDecodePointer_t)(
    _In_ PVOID Ptr
);

typedef PVOID(NTAPI* RtlAddVectoredExceptionHandler_t)(
    _In_ BOOLEAN First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler
);

typedef ULONG(NTAPI* RtlRemoveVectoredExceptionHandler_t)(
    _In_ PVOID Handle
);

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_ PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
);

typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

extern NtWriteFile_t NtWriteFile;
extern NtQueryInformationProcess_t NtQueryInformationProcess;
extern NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
extern NtCreateSection_t NtCreateSection;
extern ZwMapViewOfSection_t ZwMapViewOfSection;
extern RtlAllocateHeap_t RtlAllocateHeap;
extern RtlFreeHeap_t RtlFreeHeap;
extern RtlCreateEnvironment_t RtlCreateEnvironment;
extern RtlDestroyEnvironment_t RtlDestroyEnvironment;
extern RtlSetEnvironmentVariable_t RtlSetEnvironmentVariable;
extern RtlQueryEnvironmentVariable_U_t RtlQueryEnvironmentVariable_U;
extern RtlInitializeCriticalSection_t RtlInitializeCriticalSection;
extern RtlEncodePointer_t RtlEncodePointer;
extern RtlDecodePointer_t RtlDecodePointer;
extern RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler;
extern RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler;
extern NtQuerySystemInformation_t NtQuerySystemInformation;
extern NtTerminateProcess_t NtTerminateProcess;
extern NtSetInformationProcess_t NtSetInformationProcess;

__forceinline
PWSTR
NTAPI
RtlGetNtSystemRoot(
    VOID
    )
{
    if (NtCurrentPeb()->SharedData && NtCurrentPeb()->SharedData->ServiceSessionId)
        return NtCurrentPeb()->SharedData->NtSystemRoot;
    else
        return USER_SHARED_DATA->NtSystemRoot;
}

__forceinline
VOID
RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PCWSTR SourceString
    )
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

__forceinline
VOID
RtlInitEmptyUnicodeString(
    _Out_ PUNICODE_STRING UnicodeString,
    _In_ PWCHAR Buffer,
    _In_ USHORT BufferSize
)
{
    UnicodeString->Buffer = Buffer;
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = BufferSize;
}

__forceinline 
VOID 
RtlCopyUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString
    )
{
    DestinationString->Length = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;
    DestinationString->Buffer = SourceString->Buffer;
}

__forceinline
NTSTATUS
RtlAppendUnicodeStringToString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString
)
{
    DestinationString->Length += SourceString->Length;
    if (DestinationString->Length > DestinationString->MaximumLength) {
        return STATUS_BUFFER_OVERFLOW;
    }
    else {
        DestinationString->Buffer[DestinationString->Length / sizeof(WCHAR)] = UNICODE_NULL;
        memcpy(&DestinationString->Buffer[DestinationString->Length / sizeof(WCHAR)], SourceString->Buffer, SourceString->Length);
        return 0;
    }
}

NTSTATUS NTAPI LoadDLL(_In_ PUNICODE_STRING DllName, _Out_ PVOID* BaseAddress);

#ifdef __cplusplus
}
#endif

#endif // WINFNC_H
