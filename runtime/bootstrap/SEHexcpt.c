#include <bootstrap/core.h>
#include <hash/ntdll.h>
#include <windows.h>
#include <winifnc.h>

typedef LONG (WINAPI *CSpecificHandler_t)(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    PVOID EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    PVOID DispatcherContext
);
CSpecificHandler_t C_specific_handler = nullptr;

LONG WINAPI __C_specific_handler(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    PVOID EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    PVOID DispatcherContext)
{
    if (C_specific_handler) {
        return C_specific_handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
    }

    PLDR_DATA_TABLE_ENTRY ntdll_module = FindInMemoryModuleByHash(NTDLL_HASH);
    if (!ntdll_module) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    C_specific_handler = (CSpecificHandler_t)FindExportByHash(ntdll_module, __C_specific_handler_HASH);
    
    if (!C_specific_handler) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return C_specific_handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}
