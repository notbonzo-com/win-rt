#include <bootstrap/core.h>
#include <winifnc.h>
#include <windows.h>
#include <hash/ntdll.h>
#include <bootstrap/core.h>
#include <dbgio.h>

extern int main(int argc, char **argv);

/* this function returns into ntdll!RtlUserThreadStart */
int _start() {
    int status = 0;
    PLDR_DATA_TABLE_ENTRY ntdll = FindInMemoryModuleByHash(NTDLL_HASH);
    if ((status = ResolveSyscallTable(ntdll)) != 0)
        return status;

    status = main(0, nullptr);

    return status; /* You can return into RtlUserThreadStart */
}