#ifndef WINIFNC_H
#define WINIFNC_H

#include <windows.h>
#include <string.h>
#include <bootstrap/core.h>

#ifdef __cplusplus
extern "C" {
#endif

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
NTSTATUS RtlAppendUnicodeStringToString(PUNICODE_STRING DestinationString, PUNICODE_STRING SourceString)
{
    USHORT newLength = DestinationString->Length + SourceString->Length;
    if (newLength > DestinationString->MaximumLength - sizeof(UNICODE_NULL))
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    memcpy((BYTE*)DestinationString->Buffer + DestinationString->Length,
           SourceString->Buffer,
           SourceString->Length);
    DestinationString->Length = newLength;
    DestinationString->Buffer[newLength / sizeof(WCHAR)] = UNICODE_NULL;
    return 0;
}

__forceinline
int RtlEqualUnicodeString(const UNICODE_STRING *String1, const UNICODE_STRING *String2, int CaseInsensitive)
{
    if (String1->Length != String2->Length)
        return 0;
    size_t count = String1->Length / sizeof(WCHAR);
    if (CaseInsensitive)
    {
        return (wcsnicmp(String1->Buffer, String2->Buffer, count) == 0);
    }
    else
    {
        return (wcsncmp(String1->Buffer, String2->Buffer, count) == 0);
    }
}

__forceinline
NTSTATUS RtlDuplicateUnicodeString(unsigned long Flags, const UNICODE_STRING *SourceString, PUNICODE_STRING DestinationString)
{
    size_t newSize = SourceString->Length + sizeof(UNICODE_NULL);
    if (newSize > (1024 * 1024))
    {
        return STATUS_BUFFER_OVERFLOW;
    }
    PWSTR newBuffer = (PWSTR)__bootstrap_malloc(newSize);
    if (!newBuffer)
    {
        return STATUS_NO_MEMORY;
    }
    memcpy(newBuffer, SourceString->Buffer, SourceString->Length);
    newBuffer[SourceString->Length / sizeof(WCHAR)] = UNICODE_NULL;

    DestinationString->Buffer = newBuffer;
    DestinationString->Length = SourceString->Length;
    DestinationString->MaximumLength = (USHORT)newSize;
    return 0;
}

__forceinline
VOID RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
{
    if (UnicodeString->Buffer)
    {
        __bootstrap_free(UnicodeString->Buffer);
        UnicodeString->Buffer = nullptr;
        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
    }
}

__forceinline
VOID
RtlInitAnsiString(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_ PCSZ SourceString
    )
{
    if (SourceString)
    {
        DestinationString->Length = (USHORT)strlen(SourceString);
        DestinationString->MaximumLength = DestinationString->Length + 1;
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PCHAR)SourceString;
}

__forceinline
NTSTATUS
RtlAnsiStringToUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ const ANSI_STRING *SourceString,
    _In_ BOOLEAN AllocateDestinationString
)
{
    if (!SourceString || !SourceString->Buffer)
    {
        DestinationString->Buffer = nullptr;
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        return 0;
    }
    
    size_t ansiLen = SourceString->Length;
    size_t requiredSize = (ansiLen + 1) * sizeof(WCHAR);
    PWSTR buffer = nullptr;
    
    if (AllocateDestinationString)
    {
        buffer = (PWSTR)__bootstrap_malloc(requiredSize);
        if (!buffer)
            return STATUS_NO_MEMORY;
    }
    else
    {
        if (DestinationString->MaximumLength < requiredSize)
            return STATUS_BUFFER_OVERFLOW;
        buffer = DestinationString->Buffer;
    }
    
    for (size_t i = 0; i < ansiLen; i++)
    {
        buffer[i] = (WCHAR)SourceString->Buffer[i]; /* todo this might not be the best */
    }
    buffer[ansiLen] = UNICODE_NULL;
    
    DestinationString->Buffer = buffer;
    DestinationString->Length = (USHORT)(ansiLen * sizeof(WCHAR));
    DestinationString->MaximumLength = (USHORT)requiredSize;
    
    return 0;
}

__forceinline
LONG RtlCompareUnicodeString(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
)
{
    if (CaseInSensitive)
        return wcsicmp(String1->Buffer, String2->Buffer);
    else
        return wcscmp(String1->Buffer, String2->Buffer);
}

__forceinline
NTSTATUS
RtlInitUnicodeStringEx(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
    )
{
    if (!DestinationString)
        return STATUS_INVALID_PARAMETER;

    if (SourceString)
    {
        size_t length = wcslen(SourceString) * sizeof(WCHAR);
        if (length > UNICODE_STRING_MAX_BYTES)
            return STATUS_NAME_TOO_LONG;

        DestinationString->Length = (USHORT)length;
        DestinationString->MaximumLength = DestinationString->Length + sizeof(UNICODE_NULL);
        DestinationString->Buffer = (PWSTR)SourceString;
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }

    return 0;
}

__forceinline
PVOID RtlpAllocateStringMemory(SIZE_T size, LONG) {
    return __bootstrap_malloc(size);
}

__forceinline
NTSTATUS NTAPI RtlCharToInteger(PCSZ str, ULONG base, PULONG value)
{
    CHAR chCurrent;
    int digit;
    ULONG RunningTotal = 0;
    char bMinus = 0;

    while (*str != '\0' && *str <= ' ') str++;

    if (*str == '+')
    {
        str++;
    }
    else if (*str == '-')
    {
        bMinus = 1;
        str++;
    }

    if (base == 0)
    {
        base = 10;

        if (str[0] == '0')
        {
            if (str[1] == 'b')
            {
                str += 2;
                base = 2;
            }
            else if (str[1] == 'o')
            {
                str += 2;
                base = 8;
            }
            else if (str[1] == 'x')
            {
                str += 2;
                base = 16;
            }
        }
    }
    else if (base != 2 && base != 8 && base != 10 && base != 16)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (value == nullptr) return STATUS_ACCESS_VIOLATION;

    while (*str != '\0')
    {
        chCurrent = *str;

        if (chCurrent >= '0' && chCurrent <= '9')
        {
            digit = chCurrent - '0';
        }
        else if (chCurrent >= 'A' && chCurrent <= 'Z')
        {
            digit = chCurrent - 'A' + 10;
        }
        else if (chCurrent >= 'a' && chCurrent <= 'z')
        {
            digit = chCurrent - 'a' + 10;
        }
        else
        {
            digit = -1;
        }

        if (digit < 0 || digit >= (int)base) break;

        RunningTotal = RunningTotal * base + digit;
        str++;
    }

    *value = bMinus ? (0 - RunningTotal) : RunningTotal;
    return 0;
}

__forceinline
VOID InsertTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
)
{
    PLIST_ENTRY LastEntry = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = LastEntry;
    LastEntry->Flink = Entry;
    ListHead->Blink = Entry;
}

__forceinline
VOID InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY FirstEntry = ListHead->Flink;
    Entry->Flink = FirstEntry;
    Entry->Blink = ListHead;
    FirstEntry->Blink = Entry;
    ListHead->Flink = Entry;
}

__forceinline
VOID RemoveEntryList(PLIST_ENTRY Entry)
{
    PLIST_ENTRY Prev = Entry->Blink;
    PLIST_ENTRY Next = Entry->Flink;
    Prev->Flink = Next;
    Next->Blink = Prev;
    Entry->Flink = Entry->Blink = nullptr;
}

__forceinline
int IsListEmpty(PLIST_ENTRY ListHead)
{
    return (ListHead->Flink == ListHead);
}

__forceinline
BOOLEAN NTAPI RtlpCheckForActiveDebugger()
{
    return NtCurrentPeb()->BeingDebugged;
}

__forceinline
void YieldProcessor()
{
    __asm__ __volatile__("pause" : : : "memory");
}

__forceinline
void DbgBreakPoint()
{
    __asm__ __volatile__("int $0x3");
}

__forceinline
unsigned long long __ull_rshift(const unsigned long long Mask, int Bit)
{
    return Mask >> Bit;
}

#define Int64ShrlMod32(a,b) __ull_rshift(a,b)
#define UInt32x32To64(a,b) ((unsigned __int64)(unsigned int)(a)*(unsigned __int64)(unsigned int)(b))

#ifdef __cplusplus
}
#endif

#endif // WINIFNC_H
