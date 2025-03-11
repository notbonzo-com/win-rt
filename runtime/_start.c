#include <windows.h>
#include <winfnc.h>
#include <string.h>
#include <hash/ntdll.h>
#include <bootstrap/core.h>

extern int main(int argc, char **argv);

/* this function returns into ntdll!RtlUserThreadStart */
/* at this point we have a 1MiB stack and a 1MiB heap managed by __bootstrap_alloc */
int _start() {
    if (!__bootstrap_init())
        return -808;

    int status = main(0, nullptr);

    return status; /* You can return into RtlUserThreadStart */
}

NtWriteFile_t NtWriteFile = nullptr;
NtQueryInformationProcess_t NtQueryInformationProcess = nullptr;
NtAllocateVirtualMemory_t NtAllocateVirtualMemory = nullptr;
NtCreateSection_t NtCreateSection = nullptr;
ZwMapViewOfSection_t ZwMapViewOfSection = nullptr;
RtlAllocateHeap_t RtlAllocateHeap = nullptr;
RtlFreeHeap_t RtlFreeHeap = nullptr;
RtlCreateEnvironment_t RtlCreateEnvironment = nullptr;
RtlDestroyEnvironment_t RtlDestroyEnvironment = nullptr;
RtlSetEnvironmentVariable_t RtlSetEnvironmentVariable = nullptr;
RtlQueryEnvironmentVariable_U_t RtlQueryEnvironmentVariable_U = nullptr;
RtlInitializeCriticalSection_t RtlInitializeCriticalSection = nullptr;
RtlEncodePointer_t RtlEncodePointer = nullptr;
RtlDecodePointer_t RtlDecodePointer = nullptr;
RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = nullptr;
RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler = nullptr;
NtQuerySystemInformation_t NtQuerySystemInformation = nullptr;
NtTerminateProcess_t NtTerminateProcess = nullptr;
NtSetInformationProcess_t NtSetInformationProcess = nullptr;

bool __bootstrap_init() {
    PLDR_DATA_TABLE_ENTRY ntdll_module = __bootstrap_find_module(NTDLL_HASH);
    if (!ntdll_module) {
        return false;
    }

    NtWriteFile = (NtWriteFile_t)__bootstrap_get_export(ntdll_module, NTWRITEFILE_HASH);
    if (!NtWriteFile) {
        return false;
    }

    NtQueryInformationProcess = (NtQueryInformationProcess_t)__bootstrap_get_export(ntdll_module, NTQUERYINFORMATIONPROCESS_HASH);
    if (!NtQueryInformationProcess) {
        __bootstrap_print("NtQueryInformationProcess failed to be resolved\n");
        return false;
    }

    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)__bootstrap_get_export(ntdll_module, NTALLOCATEVIRTUALMEMORY_HASH);
    if (!NtAllocateVirtualMemory) {
        __bootstrap_print("NtAllocateVirtualMemory failed to be resolved\n");
        return false;
    }

    NtCreateSection = (NtCreateSection_t)__bootstrap_get_export(ntdll_module, NTCREATESECTION_HASH);
    if (!NtCreateSection) {
        __bootstrap_print("NtCreateSection failed to be resolved\n");
        return false;
    }

    ZwMapViewOfSection = (ZwMapViewOfSection_t)__bootstrap_get_export(ntdll_module, NTMAPVIEWOFSECTION_HASH);
    if (!ZwMapViewOfSection) {
        __bootstrap_print("ZwMapViewOfSection failed to be resolved\n");
        return false;
    }

    RtlAllocateHeap = (RtlAllocateHeap_t)__bootstrap_get_export(ntdll_module, RTLALLOCATEHEAP_HASH);
    if (!RtlAllocateHeap) {
        __bootstrap_print("RtlAllocateHeap failed to be resolved\n");
        return false;
    }

    RtlFreeHeap = (RtlFreeHeap_t)__bootstrap_get_export(ntdll_module, RTLFREEHEAP_HASH);
    if (!RtlFreeHeap) {
        __bootstrap_print("RtlFreeHeap failed to be resolved\n");
        return false;
    }

    RtlCreateEnvironment = (RtlCreateEnvironment_t)__bootstrap_get_export(ntdll_module, RTLCREATEENVIRONMENT_HASH);
    if (!RtlCreateEnvironment) {
        __bootstrap_print("RtlCreateEnvironment failed to be resolved\n");
        return false;
    }

    RtlDestroyEnvironment = (RtlDestroyEnvironment_t)__bootstrap_get_export(ntdll_module, RTLDESTROYENVIRONMENT_HASH);
    if (!RtlDestroyEnvironment) {
        __bootstrap_print("RtlDestroyEnvironment failed to be resolved\n");
        return false;
    }

    RtlSetEnvironmentVariable = (RtlSetEnvironmentVariable_t)__bootstrap_get_export(ntdll_module, RTLSETENVIRONMENTVARIABLE_HASH);
    if (!RtlSetEnvironmentVariable) {
        __bootstrap_print("RtlSetEnvironmentVariable failed to be resolved\n");
        return false;
    }

    RtlQueryEnvironmentVariable_U = (RtlQueryEnvironmentVariable_U_t)__bootstrap_get_export(ntdll_module, RTLQUERYENVIRONMENTVARIABLE_U_HASH);
    if (!RtlQueryEnvironmentVariable_U) {
        __bootstrap_print("RtlQueryEnvironmentVariable_U failed to be resolved\n");
        return false;
    }

    RtlInitializeCriticalSection = (RtlInitializeCriticalSection_t)__bootstrap_get_export(ntdll_module, RTLINITIALIZECRITICALSECTION_HASH);
    if (!RtlInitializeCriticalSection) {
        __bootstrap_print("RtlInitializeCriticalSection failed to be resolved\n");
        return false;
    }

    RtlEncodePointer = (RtlEncodePointer_t)__bootstrap_get_export(ntdll_module, RTLENCODEPOINTER_HASH);
    if (!RtlEncodePointer) {
        __bootstrap_print("RtlEncodePointer failed to be resolved\n");
        return false;
    }

    RtlDecodePointer = (RtlDecodePointer_t)__bootstrap_get_export(ntdll_module, RTLDECODEPOINTER_HASH);
    if (!RtlDecodePointer) {
        __bootstrap_print("RtlDecodePointer failed to be resolved\n");
        return false;
    }

    RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)__bootstrap_get_export(ntdll_module, RTLADDVECTOREDEXCEPTIONHANDLER_HASH);
    if (!RtlAddVectoredExceptionHandler) {
        __bootstrap_print("RtlAddVectoredExceptionHandler failed to be resolved\n");
        return false;
    }

    RtlRemoveVectoredExceptionHandler = (RtlRemoveVectoredExceptionHandler_t)__bootstrap_get_export(ntdll_module, RTLREMOVEVECTOREDEXCEPTIONHANDLER_HASH);
    if (!RtlRemoveVectoredExceptionHandler) {
        __bootstrap_print("RtlRemoveVectoredExceptionHandler failed to be resolved\n");
        return false;
    }

    NtQuerySystemInformation = (NtQuerySystemInformation_t)__bootstrap_get_export(ntdll_module, NTQUERYSYSTEMINFORMATION_HASH);
    if (!NtQuerySystemInformation) {
        __bootstrap_print("NtQuerySystemInformation failed to be resolved\n");
        return false;
    }

    NtTerminateProcess = (NtTerminateProcess_t)__bootstrap_get_export(ntdll_module, NTTERMINATEPROCESS_HASH);
    if (!NtTerminateProcess) {
        __bootstrap_print("NtTerminateProcess failed to be resolved\n");
        return false;
    }

    NtSetInformationProcess = (NtSetInformationProcess_t)__bootstrap_get_export(ntdll_module, NTSETINFORMATIONPROCESS_HASH);
    if (!NtSetInformationProcess) {
        __bootstrap_print("NtSetInformationProcess failed to be resolved\n");
        return false;
    }

    return true;
}

void __bootstrap_print(const char* msg) {
    IO_STATUS_BLOCK io_status;
    NtWriteFile(NtCurrentPeb()->ProcessParameters->StandardOutput, nullptr, nullptr, nullptr, &io_status, (PVOID)msg, (ULONG)strlen(msg), nullptr, nullptr);
}