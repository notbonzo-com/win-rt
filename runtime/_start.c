#include <winifnc.h>
#include <windows.h>
#include <hash/ntdll.h>
#include <bootstrap/core.h>

extern int main(int argc, char **argv);

/* this function returns into ntdll!RtlUserThreadStart */
int _start() {

    int status = main(0, nullptr);

    return status; /* You can return into RtlUserThreadStart */
}