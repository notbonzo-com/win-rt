#include <windows.h>
#include <winifnc.h>
#include <string.h>
#include <ntdll.h>

PLDR_DATA_TABLE_ENTRY LdrpLoadedDllHandleCache, LdrpGetModuleHandleCache;
PTEB LdrpTopLevelDllBeingLoadedTeb = nullptr;
PLDR_DATA_TABLE_ENTRY LdrpCurrentDllInitializer = nullptr;
WORD PrefixSize = sizeof(L"api-") - sizeof(WCHAR);
WORD ExtensionSize = sizeof(L".dll") - sizeof(WCHAR);
const ULONGLONG API_ = (ULONGLONG)0x2D004900500041; 
const ULONGLONG EXT_ = (ULONGLONG)0x2D005400580045; 
UNICODE_STRING LdrApiDefaultExtension = RTL_CONSTANT_STRING(L".DLL");
UNICODE_STRING LdrpDefaultPath;
UNICODE_STRING LdrpKnownDllPath;
HANDLE LdrpKnownDllObjectDirectory;

#define LDR_HASH_TABLE_ENTRIES   32
#define LDR_GET_HASH_ENTRY(x) (towupper((x)) & (LDR_HASH_TABLE_ENTRIES - 1))
LIST_ENTRY LdrpHashTable[LDR_HASH_TABLE_ENTRIES];

BOOLEAN NTAPI RtlDispatchException(_In_ PEXCEPTION_RECORD ExceptionRecord, _In_ PCONTEXT ContextRecord)
{
    BOOLEAN Handled;
 
    if (RtlCallVectoredExceptionHandlers(ExceptionRecord, ContextRecord))
    {
        RtlCallVectoredContinueHandlers(ExceptionRecord, ContextRecord);
 
        return true;
    }
 
    Handled = RtlpUnwindInternal(nullptr, nullptr, ExceptionRecord, 0, ContextRecord, nullptr, UNW_FLAG_EHANDLER);
 
    RtlCallVectoredContinueHandlers(ExceptionRecord, ContextRecord);
 
    return Handled;
}

VOID NTAPI RtlRaiseStatus( _In_ NTSTATUS Status)
{
    EXCEPTION_RECORD ExceptionRecord;
    CONTEXT Context;
 
    RtlCaptureContext(&Context);
 
    ExceptionRecord.ExceptionAddress = _ReturnAddress();
    ExceptionRecord.ExceptionCode  = Status;
    ExceptionRecord.ExceptionRecord = nullptr;
    ExceptionRecord.NumberParameters = 0;
    ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
 
    Context.ContextFlags = CONTEXT_FULL;
 
    if (RtlpCheckForActiveDebugger())
    {
        ZwRaiseException(&ExceptionRecord, &Context, true);
    }
    else
    {
        RtlDispatchException(&ExceptionRecord, &Context);
 
        Status = ZwRaiseException(&ExceptionRecord, &Context, false);
    }
 
    RtlRaiseStatus(Status);
}

BOOLEAN NTAPI LdrpCheckForLoadedDllHandle( _In_ PVOID Base, _Out_ PLDR_DATA_TABLE_ENTRY* LdrEntry)
{
    PLDR_DATA_TABLE_ENTRY Current;
    PLIST_ENTRY ListHead, Next;

    if ((LdrpLoadedDllHandleCache) &&
        (LdrpLoadedDllHandleCache->DllBase == Base))
    {
        *LdrEntry = LdrpLoadedDllHandleCache;
        return true;
    }
 
    ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Next = ListHead->Flink;
    while (Next != ListHead)
    {
        Current = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
 
        if ((Current->InMemoryOrderLinks.Flink) && (Base == Current->DllBase))
        {
            LdrpLoadedDllHandleCache = Current;
 
            *LdrEntry = Current;
            return true;
        }
 
        Next = Next->Flink;
    }
 
    return false;
}

PIMAGE_SECTION_HEADER RtlImageRvaToSection(const IMAGE_NT_HEADERS* NtHeader, PVOID BaseAddress, ULONG Rva)
{
    PIMAGE_SECTION_HEADER Section;
    ULONG Va;
    ULONG Count;
 
    Count = SWAPW(NtHeader->FileHeader.NumberOfSections);
    Section = IMAGE_FIRST_SECTION(NtHeader);
 
    while (Count--)
    {
        Va = SWAPD(Section->VirtualAddress);
        if ((Va <= Rva) && (Rva < Va + SWAPD(Section->SizeOfRawData)))
            return Section;
        Section++;
    }
 
    return nullptr;
}

PVOID RtlImageRvaToVa(const IMAGE_NT_HEADERS* NtHeader, PVOID BaseAddress, ULONG Rva, PIMAGE_SECTION_HEADER* SectionHeader)
{
    PIMAGE_SECTION_HEADER Section = nullptr;
 
    if (SectionHeader)
        Section = *SectionHeader;
 
    if ((Section == nullptr) ||
        (Rva < SWAPD(Section->VirtualAddress)) ||
        (Rva >= SWAPD(Section->VirtualAddress) + SWAPD(Section->SizeOfRawData)))
    {
        Section = RtlImageRvaToSection(NtHeader, BaseAddress, Rva);
        if (Section == nullptr)
            return nullptr;
 
        if (SectionHeader)
            *SectionHeader = Section;
    }
 
    return (PVOID)((ULONG_PTR)BaseAddress + Rva +
                   (ULONG_PTR)SWAPD(Section->PointerToRawData) -
                   (ULONG_PTR)SWAPD(Section->VirtualAddress));
}

IMAGE_NT_HEADERS* RtlImageNtHeader(void* data)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)data;
    IMAGE_NT_HEADERS* NtHeaders;
    PCHAR NtHeaderPtr;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    NtHeaderPtr = ((PCHAR)data) + DosHeader->e_lfanew;
    NtHeaders = (IMAGE_NT_HEADERS*)NtHeaderPtr;
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return NtHeaders;
} 	

PVOID RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size)
{
    IMAGE_NT_HEADERS* NtHeader;
    ULONG Va;
 
    if ((ULONG_PTR)BaseAddress & 1)
    {
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress & ~1);
        MappedAsImage = false;
    }
 
    NtHeader = RtlImageNtHeader(BaseAddress);
    if (NtHeader == nullptr)
        return nullptr;
 
    if (Directory >= SWAPD(NtHeader->OptionalHeader.NumberOfRvaAndSizes))
        return nullptr;
 
    Va = SWAPD(NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress);
    if (Va == 0)
        return nullptr;
 
    *Size = SWAPD(NtHeader->OptionalHeader.DataDirectory[Directory].Size);
 
    if (MappedAsImage || Va < SWAPD(NtHeader->OptionalHeader.SizeOfHeaders))
        return (PVOID)((ULONG_PTR)BaseAddress + Va);
 
    return RtlImageRvaToVa(NtHeader, BaseAddress, Va, nullptr);
}

USHORT NTAPI LdrpNameToOrdinal(_In_ LPSTR ImportName, _In_ ULONG NumberOfNames, _In_ PVOID ExportBase, _In_ PULONG NameTable, _In_ PUSHORT OrdinalTable)
{
    LONG Start, End, Next, CmpResult;
 
    Start = Next = 0;
    End = NumberOfNames - 1;
    while (End >= Start)
    {
        Next = (Start + End) >> 1;
 
        CmpResult = strcmp(ImportName, (PCHAR)((ULONG_PTR)ExportBase + NameTable[Next]));
 
        if (!CmpResult) break;
 
        if (CmpResult < 0)
        {
            End = Next - 1;
        }
        else if (CmpResult > 0)
        {
            Start = Next + 1;
        }
    }
 
    if (End < Start) return -1;
 
    return OrdinalTable[Next];
}

static DWORD LdrpApisetVersion()
{
    static DWORD CachedApisetVersion = ~0u;
 
    if (CachedApisetVersion == ~0u)
    {
        DWORD CompatVersion = USER_SHARED_DATA->AppCompatFlag;
 
        switch (CompatVersion)
        {
            case 0:
                break;
            case _WIN32_WINNT_VISTA:
                CachedApisetVersion = 0;
                break;
            case _WIN32_WINNT_WIN7:
                CachedApisetVersion = APISET_WIN7;
                break;
            case _WIN32_WINNT_WIN8:
                CachedApisetVersion = APISET_WIN8;
                break;
            case _WIN32_WINNT_WINBLUE:
                CachedApisetVersion = APISET_WIN81;
                break;
            case _WIN32_WINNT_WIN10:
                CachedApisetVersion = APISET_WIN10;
                break;
            default:
                CachedApisetVersion = 0;
                break;
        }
    }
 
    return CachedApisetVersion;
}

NTSTATUS ApiSetResolveToHost(_In_ DWORD ApisetVersion, _In_ PUNICODE_STRING ApiToResolve, _Out_ PBOOLEAN Resolved, _Out_ PUNICODE_STRING Output )
{
    if (ApiToResolve->Length < PrefixSize)
    {
        *Resolved = false;
        return 0;
    }
 
    PWSTR ApiSetNameBuffer = ApiToResolve->Buffer;
    ULONGLONG ApiSetNameBufferPrefix = ((ULONGLONG *)ApiSetNameBuffer)[0] & 0xFFFFFFDFFFDFFFDF;

    if (!(ApiSetNameBufferPrefix == API_ || ApiSetNameBufferPrefix == EXT_))
    {
        *Resolved = false;
        return 0;
    }
 
    UNICODE_STRING Tmp = *ApiToResolve;
    const WCHAR *Extension = Tmp.Buffer + (Tmp.Length - ExtensionSize) / sizeof(WCHAR);
    if (!wcsnicmp(Extension, L".dll", ExtensionSize / sizeof(WCHAR)))
        Tmp.Length -= ExtensionSize;
 
    LONG UBnd = g_ApisetsCount - 1;
    LONG LBnd = 0;
    while (LBnd <= UBnd)
    {
        LONG Index = (UBnd - LBnd) / 2 + LBnd;
 
        LONG result = RtlCompareUnicodeString(&Tmp, &g_Apisets[Index].Name, true);
        if (result == 0)
        {
            if (g_Apisets[Index].dwOsVersions & ApisetVersion)
            {
                *Resolved = true;
                *Output = g_Apisets[Index].Target;
            }
            return 0;
        }
        else if (result < 0)
        {
            UBnd = Index - 1;
        }
        else
        {
            LBnd = Index + 1;
        }
    }
    *Resolved = false;
    return 0;
}

NTSTATUS NTAPI LdrpApplyFileNameRedirection(_In_ PUNICODE_STRING OriginalName, _In_ PUNICODE_STRING Extension, _Inout_ PUNICODE_STRING StaticString, _Inout_ PUNICODE_STRING DynamicString, _Inout_ PUNICODE_STRING* NewName, _Out_ PBOOLEAN RedirectedDll)
{
    if (!OriginalName)
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    if (!DynamicString && !StaticString)
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    if (!NewName)
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    *RedirectedDll = false;
 
    UNICODE_STRING ApisetName = {0};
    NTSTATUS Status = 0;
 
    DWORD ApisetVersion = LdrpApisetVersion();
    if (ApisetVersion)
    {
        Status = ApiSetResolveToHost(ApisetVersion, OriginalName, RedirectedDll, &ApisetName);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
 
    if (*RedirectedDll)
    {
        UNICODE_STRING NtSystemRoot;
        static const UNICODE_STRING System32 = RTL_CONSTANT_STRING(L"\\System32\\");
        PUNICODE_STRING ResultPath = nullptr;
 
        RtlInitUnicodeString(&NtSystemRoot, USER_SHARED_DATA->NtSystemRoot);
 
        SIZE_T Needed = System32.Length + ApisetName.Length + NtSystemRoot.Length + sizeof(UNICODE_NULL);
 
        if (StaticString && StaticString->MaximumLength >= (USHORT)Needed)
        {
            StaticString->Length = 0;
            ResultPath = StaticString;
        }
        else if (DynamicString)
        {
            DynamicString->Buffer = RtlpAllocateStringMemory(Needed, TAG_USTR);
            if (DynamicString->Buffer == nullptr)
            {
                return STATUS_NO_MEMORY;
            }
            DynamicString->MaximumLength = (USHORT)Needed;
            DynamicString->Length = 0;
 
            ResultPath = DynamicString;
        }
        else
        {
            return STATUS_INVALID_PARAMETER;
        }
 
        RtlAppendUnicodeStringToString(ResultPath, &NtSystemRoot);
        RtlAppendUnicodeStringToString(ResultPath, &System32);
        RtlAppendUnicodeStringToString(ResultPath, &ApisetName);
        *NewName = ResultPath;
    }
    else
    {
        Status = STATUS_SXS_KEY_NOT_FOUND; /* fuck this shit */
        static char* fuck_this_shit = "fuck this SxS shit\n";
        (void)fuck_this_shit;
 
        if (NT_SUCCESS(Status))
        {
            *RedirectedDll = true;
        }
        else if (Status == STATUS_SXS_KEY_NOT_FOUND)
        {
            Status = 0;
        }
        else
        {
            if (DynamicString && DynamicString->Buffer)
                RtlFreeUnicodeString(DynamicString);
            return Status;
        }
    }
 
    return Status;
}

ULONG NTAPI LdrpClearLoadInProgress()
{
    PLIST_ENTRY ListHead, Entry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    ULONG ModulesCount = 0;
 
    ListHead = &NtCurrentPeb()->Ldr->InInitializationOrderModuleList;
    Entry = ListHead->Flink;
    while (Entry != ListHead)
    {
        LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
 
        LdrEntry->Flags &= ~LDRP_LOAD_IN_PROGRESS;
 
        if ((LdrEntry->EntryPoint) &&
            !(LdrEntry->Flags & LDRP_ENTRY_PROCESSED))
        {
            ModulesCount++;
        }
 
        Entry = Entry->Flink;
    }

    return ModulesCount;
}

PVOID NTAPI LdrpFetchAddressOfSecurityCookie(PVOID BaseAddress, ULONG SizeOfImage)
{
    PIMAGE_LOAD_CONFIG_DIRECTORY ConfigDir;
    ULONG DirSize;
    PVOID Cookie = nullptr;
 
    if (!RtlImageNtHeader(BaseAddress)) return nullptr;
 
    ConfigDir = RtlImageDirectoryEntryToData(BaseAddress, true, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &DirSize);
 
    if (!ConfigDir ||
        (DirSize != 64 && ConfigDir->Size != DirSize) ||
        (ConfigDir->Size < 0x48))
        return nullptr;
 
    Cookie = (PVOID)ConfigDir->SecurityCookie;
 
    if ((PCHAR)Cookie <= (PCHAR)BaseAddress ||
        (PCHAR)Cookie >= (PCHAR)BaseAddress + SizeOfImage)
    {
        Cookie = nullptr;
    }
 
    return Cookie;
}

PVOID NTAPI LdrpInitSecurityCookie(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PULONG_PTR Cookie;
    ULONG_PTR NewCookie;
 
    Cookie = LdrpFetchAddressOfSecurityCookie(LdrEntry->DllBase, LdrEntry->SizeOfImage);
 
    if (Cookie)
    {
        if ((*Cookie == DEFAULT_SECURITY_COOKIE) ||
            (*Cookie == 0xBB40))
        { 
            NewCookie = USER_SHARED_DATA->DUMMYUNIONNAME3.TickCountQuad;
            NewCookie ^= (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
            NewCookie ^= (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
 
            while (USER_SHARED_DATA->SystemTime.High1Time != USER_SHARED_DATA->SystemTime.High2Time)
            {
                YieldProcessor();
            };
 
            NewCookie ^= Int64ShrlMod32(UInt32x32To64(USER_SHARED_DATA->TickCountMultiplier, USER_SHARED_DATA->DUMMYUNIONNAME3.TickCount.LowPart), 24) +
                (USER_SHARED_DATA->TickCountMultiplier * (USER_SHARED_DATA->DUMMYUNIONNAME3.TickCount.High1Time << 8));
 
            if (*Cookie == 0xBB40) NewCookie &= 0xFFFF;
 
            if ((NewCookie == 0) || (NewCookie == *Cookie))
            {
                NewCookie = *Cookie - 1;
            }
 
            *Cookie = NewCookie;
        }
    }
 
    return Cookie;
}

NTSTATUS NTAPI LdrQueryImageFileExecutionOptionsEx(_In_ PUNICODE_STRING SubKey, _In_ PCWSTR ValueName, _In_ ULONG Type, _Out_ PVOID Buffer, _In_ ULONG BufferSize, _Out_ PULONG ReturnedLength, _In_ BOOLEAN Wow64)
{
    NTSTATUS Status;
    HANDLE KeyHandle;
 
    Status = LdrOpenImageFileOptionsKey(SubKey, Wow64, &KeyHandle);
 
    if (NT_SUCCESS(Status))
    {
        Status = LdrQueryImageFileKeyOption(KeyHandle, ValueName, Type, Buffer, BufferSize, ReturnedLength);
 
        NtClose(KeyHandle);
    }
 
    return Status;
}

RTL_PATH_TYPE NTAPI RtlDetermineDosPathNameType_U( _In_ PCWSTR Path)
{
    #define IS_PATH_SEPARATOR(x) (((x)==L'\\')||((x)==L'/'))

    if (IS_PATH_SEPARATOR(Path[0]))
    {
        if (!IS_PATH_SEPARATOR(Path[1])) return RtlPathTypeRooted;                /* \x             */
        if ((Path[2] != L'.') && (Path[2] != L'?')) return RtlPathTypeUncAbsolute;/* \\x            */
        if (IS_PATH_SEPARATOR(Path[3])) return RtlPathTypeLocalDevice;            /* \\.\x or \\?\x */
        if (Path[3]) return RtlPathTypeUncAbsolute;                               /* \\.x or \\?x   */
        return RtlPathTypeRootLocalDevice;                                        /* \\. or \\?     */
    }
    else
    {
        if (!(Path[0]) || (Path[1] != L':')) return RtlPathTypeRelative;          /* x              */
        if (IS_PATH_SEPARATOR(Path[2])) return RtlPathTypeDriveAbsolute;          /* x:\            */
        return RtlPathTypeDriveRelative;                                          /* x:             */
    }
    #undef IS_PATH_SEPARATOR
}

NTSTATUS NTAPI RtlpImageNtHeaderEx(_In_ ULONG Flags, _In_ PVOID Base, _In_ ULONG64 Size, _Out_ IMAGE_NT_HEADERS** OutHeaders)
{
    IMAGE_NT_HEADERS* NtHeaders;
    PIMAGE_DOS_HEADER DosHeader;
    BOOLEAN WantsRangeCheck;
    ULONG NtHeaderOffset;
 
    if (OutHeaders == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    *OutHeaders = nullptr;
 
    if (Flags & ~RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK)
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    if ((Base == nullptr) || (Base == (PVOID)-1))
    {
        return STATUS_INVALID_PARAMETER;
    }
 
    WantsRangeCheck = !(Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK);
    if (WantsRangeCheck)
    {
        if (Size < sizeof(IMAGE_DOS_HEADER))
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
 
    DosHeader = Base;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
 
    NtHeaderOffset = DosHeader->e_lfanew;
 
    if (NtHeaderOffset >= (256 * 1024 * 1024))
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
 
    if (WantsRangeCheck)
    {
        if ((NtHeaderOffset +
             RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader)) >= Size)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
 
    NtHeaders = (IMAGE_NT_HEADERS*)((ULONG_PTR)Base + NtHeaderOffset);
 
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
 
    *OutHeaders = NtHeaders;
    return 0;
}

BOOLEAN NTAPI LdrpCheckForLoadedDll( _In_ PWSTR DllPath, _In_ PUNICODE_STRING DllName, _In_ BOOLEAN Flag, _In_ BOOLEAN RedirectedDll, _Out_ PLDR_DATA_TABLE_ENTRY *LdrEntry)
{
    ULONG HashIndex;
    PLIST_ENTRY ListHead, ListEntry;
    PLDR_DATA_TABLE_ENTRY CurEntry;
    BOOLEAN FullPath = false;
    PWCHAR wc;
    WCHAR NameBuf[266];
    UNICODE_STRING FullDllName, NtPathName;
    ULONG Length;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE FileHandle, SectionHandle;
    IO_STATUS_BLOCK Iosb;
    PVOID ViewBase = nullptr;
    SIZE_T ViewSize = 0;
    IMAGE_NT_HEADERS* NtHeader, *NtHeader2;

    if (!DllName->Buffer || DllName->Buffer[0] == L'\0')
        return false;

lookinhash:
    if (Flag && !RedirectedDll)
    {
        HashIndex = LDR_GET_HASH_ENTRY(DllName->Buffer[0]);
        ListHead = &LdrpHashTable[HashIndex];
        ListEntry = ListHead->Flink;
        while (ListEntry != ListHead)
        {
            CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, HashLinks);
            if (RtlEqualUnicodeString(DllName, &CurEntry->BaseDllName, true))
            {
                *LdrEntry = CurEntry;
                return true;
            }
            ListEntry = ListEntry->Flink;
        }
        
        return false;
    }

    if (RedirectedDll)
    {
        FullPath = true;
        FullDllName = *DllName;
    }
    else
    {
        wc = DllName->Buffer;
        while (*wc)
        {
            if ((*wc == L'\\') || (*wc == L'/'))
            {
                FullPath = true;
                
                FullDllName.Buffer = NameBuf;
                Length = RtlDosSearchPath_U(
                    DllPath ? DllPath : LdrpDefaultPath.Buffer,
                    DllName->Buffer,
                    nullptr,
                    sizeof(NameBuf) - sizeof(UNICODE_NULL),
                    FullDllName.Buffer,
                    nullptr);
                FullDllName.Length = (USHORT)Length;
                FullDllName.MaximumLength = FullDllName.Length + sizeof(UNICODE_NULL);
                break;
            }
            wc++;
        }
    }

    if (!FullPath)
    {
        Flag = true;
        goto lookinhash;
    }

    ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    ListEntry = ListHead->Flink;
    while (ListEntry != ListHead)
    {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ListEntry = ListEntry->Flink;
        if (!CurEntry->InMemoryOrderLinks.Flink)
            continue;
        if (RtlEqualUnicodeString(&FullDllName, &CurEntry->FullDllName, true))
        {
            *LdrEntry = CurEntry;
            return true;
        }
    }

    if (!RtlDosPathNameToNtPathName_U(FullDllName.Buffer, &NtPathName, nullptr, nullptr))
        return false;

    InitializeObjectAttributes(&ObjectAttributes, &NtPathName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    Status = NtOpenFile(&FileHandle,
                        SYNCHRONIZE | FILE_EXECUTE,
                        &ObjectAttributes,
                        &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    // TODO free heap NtPathName.Buffer

    if (!NT_SUCCESS(Status))
        return false;

    Status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
                             nullptr,
                             nullptr,
                             PAGE_EXECUTE,
                             SEC_COMMIT,
                             FileHandle);
                             
    NtClose(FileHandle);

    if (!NT_SUCCESS(Status))
        return false;

    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &ViewBase,
                                0,
                                0,
                                nullptr,
                                &ViewSize,
                                ViewShare,
                                0,
                                PAGE_EXECUTE);
    NtClose(SectionHandle);

    if (!NT_SUCCESS(Status))
        return false;

    Status = RtlpImageNtHeaderEx(0, ViewBase, ViewSize, &NtHeader);
    if (!NT_SUCCESS(Status) || (NtHeader == nullptr))
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
        return false;
    }

    ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    ListEntry = ListHead->Flink;
    while (ListEntry != ListHead)
    {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ListEntry = ListEntry->Flink;
        if (!CurEntry->InMemoryOrderLinks.Flink)
            continue;

        __try
        {
            if ((CurEntry->TimeDateStamp == NtHeader->FileHeader.TimeDateStamp) &&
                (CurEntry->SizeOfImage == NtHeader->OptionalHeader.SizeOfImage))
            {
                NtHeader2 = RtlImageNtHeader(CurEntry->DllBase);
                if (memcmp(NtHeader2, NtHeader, sizeof(IMAGE_NT_HEADERS)) == sizeof(IMAGE_NT_HEADERS))
                {
                    Status = NtAreMappedFilesTheSame(CurEntry->DllBase, ViewBase);
                    if (NT_SUCCESS(Status))
                    {
                        *LdrEntry = CurEntry;
                        NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
                        return true;
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }
    }

    NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
    return false;
}

NTSTATUS NTAPI LdrpCheckForKnownDll(PWSTR DllName, PUNICODE_STRING FullDllName, PUNICODE_STRING BaseDllName, HANDLE* SectionHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Section = nullptr;
    UNICODE_STRING DllNameUnic;
    NTSTATUS Status;
    PCHAR p1;
    PWCHAR p2;
 
    if (SectionHandle) *SectionHandle = 0;
 
    if (FullDllName)
    {
        FullDllName->Length = 0;
        FullDllName->MaximumLength = 0;
        FullDllName->Buffer = nullptr;
    }
 
    if (BaseDllName)
    {
        BaseDllName->Length = 0;
        BaseDllName->MaximumLength = 0;
        BaseDllName->Buffer = nullptr;
    }
 
    if (!SectionHandle || !FullDllName || !BaseDllName)
        return STATUS_INVALID_PARAMETER;
 
    RtlInitUnicodeString(&DllNameUnic, DllName);
 
    Status = STATUS_SXS_SECTION_NOT_FOUND; /* FUCK SXS!!!!!!!!!!!1 */
 
    if (Status == STATUS_SXS_SECTION_NOT_FOUND ||
        Status == STATUS_SXS_KEY_NOT_FOUND)
    {
        BaseDllName->Length = DllNameUnic.Length;
        BaseDllName->MaximumLength = DllNameUnic.MaximumLength;
        
        BaseDllName->Buffer = __bootstrap_malloc(DllNameUnic.MaximumLength);
        if (!BaseDllName->Buffer)
        {
            Status = STATUS_NO_MEMORY;
            goto Failure;
        }
 
        memmove(BaseDllName->Buffer, DllNameUnic.Buffer, DllNameUnic.MaximumLength);
 
        FullDllName->Length = LdrpKnownDllPath.Length + BaseDllName->Length + sizeof(WCHAR);
        FullDllName->MaximumLength = FullDllName->Length + sizeof(UNICODE_NULL);
        FullDllName->Buffer = __bootstrap_malloc(FullDllName->MaximumLength);
        if (!FullDllName->Buffer)
        {
            Status = STATUS_NO_MEMORY;
            goto Failure;
        }
 
        memmove(FullDllName->Buffer, LdrpKnownDllPath.Buffer, LdrpKnownDllPath.Length);
 
        p1 = (PCHAR)FullDllName->Buffer + LdrpKnownDllPath.Length;
        p2 = (PWCHAR)p1;
        *p2++ = (WCHAR)'\\';
        p1 = (PCHAR)p2;
 
        DllNameUnic.Buffer = (PWSTR)p1;
        DllNameUnic.Length = BaseDllName->Length;
        DllNameUnic.MaximumLength = DllNameUnic.Length + sizeof(UNICODE_NULL);
 
        memmove(p1, BaseDllName->Buffer, BaseDllName->MaximumLength);
 
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DllNameUnic,
                                   OBJ_CASE_INSENSITIVE,
                                   LdrpKnownDllObjectDirectory,
                                   nullptr);
 
        Status = NtOpenSection(&Section,
                               SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
                               &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            if (Status == STATUS_OBJECT_NAME_NOT_FOUND) Status = 0;
            goto Failure;
        }
 
        *SectionHandle = Section;
        return 0;
    }
 
Failure:
    if (Section) NtClose(Section);
 
    __bootstrap_free(BaseDllName->Buffer);
    __bootstrap_free(FullDllName->Buffer);
 
    return Status;
}

NTSTATUS NTAPI LdrpMapDll(_In_ PWSTR SearchPath, _In_ PWSTR DllPath2, _In_ PWSTR DllName, _In_ PULONG DllCharacteristics, _In_ BOOLEAN Static, _In_ BOOLEAN Redirect, _Out_ PLDR_DATA_TABLE_ENTRY *DataTableEntry)
{
    NTSTATUS Status = 0;
    PTEB Teb = NtCurrentTeb();
    PPEB Peb = NtCurrentPeb();
    BOOLEAN KnownDll = false;
    HANDLE SectionHandle = nullptr;
    UNICODE_STRING FullDllName = {0};
    UNICODE_STRING BaseDllName = {0};
    UNICODE_STRING NtPathDllName = {0};
    PVOID ViewBase = nullptr;
    SIZE_T ViewSize = 0;
    PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;
    IMAGE_NT_HEADERS* NtHeaders = nullptr;
    PWCHAR p = DllName;
    WCHAR TempChar;


    if (!Redirect)
    {
        while (p && *p)
        {
            TempChar = *p++;
            if (TempChar == L'\\' || TempChar == L'/')
            {
                goto SkipKnownDllCheck;
            }
        }
        Status = LdrpCheckForKnownDll(DllName, &FullDllName, &BaseDllName, &SectionHandle);
        if (!NT_SUCCESS(Status) && (Status != STATUS_DLL_NOT_FOUND))
        {
            return Status;
        }
    }
SkipKnownDllCheck:

    if (!SectionHandle)
    {
        if (LdrpResolveDllName(SearchPath, DllName, &FullDllName, &BaseDllName))
        {
            if (!RtlDosPathNameToNtPathName_U(FullDllName.Buffer,
                                              &NtPathDllName,
                                              nullptr,
                                              nullptr))
            {
                return STATUS_OBJECT_PATH_SYNTAX_BAD;
            }

            Status = LdrpCreateDllSection(&NtPathDllName,
                                          DllPath2,
                                          DllCharacteristics,
                                          &SectionHandle);
            // TODO free heap NtPathName.Buffer

            if (!NT_SUCCESS(Status))
            {
                LdrpFreeUnicodeString(&FullDllName);
                LdrpFreeUnicodeString(&BaseDllName);
                return Status;
            }
        }
        else
        {
            if (Static)
            {
                UNICODE_STRING HardErrorDllName, HardErrorDllPath;
                ULONG_PTR HardErrorParameters[2];
                ULONG Response;

                RtlInitUnicodeString(&HardErrorDllName, DllName);
                RtlInitUnicodeString(&HardErrorDllPath, DllPath2 ? DllPath2 : L"DefaultPath");
                HardErrorParameters[0] = (ULONG_PTR)&HardErrorDllName;
                HardErrorParameters[1] = (ULONG_PTR)&HardErrorDllPath;

                NtRaiseHardError(STATUS_DLL_NOT_FOUND,
                                 2,
                                 0x00000003,
                                 HardErrorParameters,
                                 OptionOk,
                                 &Response);
            }
            return STATUS_DLL_NOT_FOUND;
        }
    }
    else
    {
        KnownDll = true;
    }

    {
        PVOID OldUserPointer = Teb->NtTib.ArbitraryUserPointer;
        Teb->NtTib.ArbitraryUserPointer = FullDllName.Buffer;

        Status = NtMapViewOfSection(SectionHandle,
                                    NtCurrentProcess(),
                                    &ViewBase,
                                    0,
                                    0,
                                    nullptr,
                                    &ViewSize,
                                    ViewShare,
                                    0,
                                    PAGE_READWRITE);

        Teb->NtTib.ArbitraryUserPointer = OldUserPointer;
    }

    if (!NT_SUCCESS(Status))
    {
        NtClose(SectionHandle);
        return Status;
    }

    NtHeaders = RtlImageNtHeader(ViewBase);
    if (!NtHeaders)
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
        NtClose(SectionHandle);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    LdrEntry = LdrpAllocateDataTableEntry(ViewBase);
    if (!LdrEntry)
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
        NtClose(SectionHandle);
        return STATUS_NO_MEMORY;
    }

    LdrEntry->Flags = Static ? LDRP_STATIC_LINK : 0;
    if (Redirect)
        LdrEntry->Flags |= LDRP_REDIRECTED;
    LdrEntry->ObsoleteLoadCount = 0;
    LdrEntry->FullDllName = FullDllName;
    LdrEntry->BaseDllName = BaseDllName;
    LdrEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(LdrEntry->DllBase);

    LdrpInsertMemoryTableEntry(LdrEntry);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA) || (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA)
    LdrpSendDllNotifications(LdrEntry, LDR_DLL_NOTIFICATION_REASON_LOADED);
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
    LdrEntry->Flags |= LDRP_LOAD_NOTIFICATIONS_SENT;
#endif
#endif

    if (Status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
    {
        IMAGE_NT_HEADERS* ImageNtHeader = RtlImageNtHeader(Peb->ImageBaseAddress);
        ULONG_PTR HardErrorParameters[1];
        ULONG Response = ResponseCancel;
        NTSTATUS HardErrorStatus = 0;

        if (ImageNtHeader->OptionalHeader.MajorSubsystemVersion <= 3)
        {
            LdrEntry->EntryPoint = 0;
            HardErrorParameters[0] = (ULONG_PTR)&LdrEntry->FullDllName;
            HardErrorStatus = NtRaiseHardError(STATUS_IMAGE_MACHINE_TYPE_MISMATCH,
                                               1,
                                               1,
                                               HardErrorParameters,
                                               OptionOkCancel,
                                               &Response);
        }

        if (NT_SUCCESS(HardErrorStatus) && Response == ResponseCancel)
        {
            RemoveEntryList(&LdrEntry->InLoadOrderLinks);
            RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
            RemoveEntryList(&LdrEntry->HashLinks);
            RtlFreeHeap(LdrpHeap, 0, LdrEntry);
            NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
            NtClose(SectionHandle);
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    else
    {
        if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
        {
            LdrEntry->Flags |= LDRP_IMAGE_DLL;
        }
        else
        {
            LdrEntry->EntryPoint = 0;
        }
    }

    if (Status == STATUS_IMAGE_NOT_AT_BASE)
    {
        LdrEntry->Flags |= LDRP_IMAGE_NOT_AT_BASE;
        ULONG_PTR PreferredBase = NtHeaders->OptionalHeader.ImageBase;
        ULONG_PTR ImageEnd = PreferredBase + ViewSize;

        BOOLEAN OverlapFound = false;
        UNICODE_STRING OverlapDll = {0};
        PLIST_ENTRY ListHead = &Peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY NextEntry = ListHead->Flink;

        while (NextEntry != ListHead)
        {
            PLDR_DATA_TABLE_ENTRY CandidateEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            NextEntry = NextEntry->Flink;

            ULONG_PTR CandidateBase = (ULONG_PTR)CandidateEntry->DllBase;
            ULONG_PTR CandidateEnd = CandidateBase + CandidateEntry->SizeOfImage;

            if (!CandidateEntry->InMemoryOrderLinks.Flink)
                continue;

            if ((PreferredBase >= CandidateBase && PreferredBase <= CandidateEnd) ||
                (ImageEnd >= CandidateBase && ImageEnd <= CandidateEnd) ||
                (CandidateBase >= PreferredBase && CandidateBase <= ImageEnd))
            {
                OverlapFound = true;
                OverlapDll = CandidateEntry->FullDllName;
                break;
            }
        }

        if (!OverlapFound)
        {
            RtlInitUnicodeString(&OverlapDll, L"Dynamically Allocated Memory");
        }

        if (LdrEntry->Flags & LDRP_IMAGE_DLL)
        {
            if (!(NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
            {
                PVOID RelocData;
                ULONG RelocDataSize = 0;
                RelocData = RtlImageDirectoryEntryToData(ViewBase,
                                                         true,
                                                         IMAGE_DIRECTORY_ENTRY_BASERELOC,
                                                         &RelocDataSize);
                if (!RelocData && !RelocDataSize)
                {
                    goto NoRelocNeeded;
                }
            }

            {
                UNICODE_STRING IllegalDll;
                BOOLEAN RelocatableDll = true;
                RtlInitUnicodeString(&IllegalDll, L"user32.dll");
                if (RtlEqualUnicodeString(&BaseDllName, &IllegalDll, true))
                    RelocatableDll = false;
                else
                {
                    RtlInitUnicodeString(&IllegalDll, L"kernel32.dll");
                    if (RtlEqualUnicodeString(&BaseDllName, &IllegalDll, true))
                        RelocatableDll = false;
                }
                if (KnownDll && !RelocatableDll)
                {
                    ULONG_PTR HardErrorParameters[2];
                    HardErrorParameters[0] = (ULONG_PTR)&IllegalDll;
                    HardErrorParameters[1] = (ULONG_PTR)&OverlapDll;

                    NtRaiseHardError(STATUS_ILLEGAL_DLL_RELOCATION,
                                     2,
                                     3,
                                     HardErrorParameters,
                                     OptionOk,
                                     &Response);
                    if (LdrpInLdrInit)
                        LdrpFatalHardErrorCount++;
                    Status = STATUS_CONFLICTING_ADDRESSES;
                    goto FailRelocate;
                }
            }

            Status = LdrpSetProtection(ViewBase, false);
            if (NT_SUCCESS(Status))
            {
                Status = LdrRelocateImageWithBias(ViewBase,
                                                  0LL,
                                                  nullptr,
                                                  0,
                                                  STATUS_CONFLICTING_ADDRESSES,
                                                  STATUS_INVALID_IMAGE_FORMAT);
                if (NT_SUCCESS(Status))
                {
                    Status = LdrpSetProtection(ViewBase, true);
                }
            }

FailRelocate:
            if (!NT_SUCCESS(Status))
            {
                RemoveEntryList(&LdrEntry->InLoadOrderLinks);
                RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
                RemoveEntryList(&LdrEntry->HashLinks);
                NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
                LdrEntry = nullptr;
            }
        }
        else
        {
NoRelocNeeded:
            Status = 0;
        }
    }

    NtClose(SectionHandle);
    *DataTableEntry = LdrEntry;
    return Status;
}


NTSTATUS NTAPI LdrpLoadDll(_In_ BOOLEAN Redirected, _In_ PWSTR DllPath, _In_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* BaseAddress, _In_ BOOLEAN CallInit)
{
    PPEB Peb = NtCurrentPeb();
    NTSTATUS Status = 0;
    WCHAR NameBuffer[MAX_PATH + 6];
    UNICODE_STRING RawDllName;
    PLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;

    if (DllName->Length >= sizeof(NameBuffer))
        return STATUS_NAME_TOO_LONG;
    RtlInitEmptyUnicodeString(&RawDllName, NameBuffer, sizeof(NameBuffer));
    RtlCopyUnicodeString(&RawDllName, DllName);

    BOOLEAN GotExtension = false;
    if (RawDllName.Length / sizeof(WCHAR) > 0)
    {
        PWSTR p = RawDllName.Buffer + (RawDllName.Length / sizeof(WCHAR)) - 1;
        while (p >= RawDllName.Buffer)
        {
            if (*p == L'.')
            {
                GotExtension = true;
                break;
            }
            else if (*p == L'\\')
            {
                break;
            }
            p--;
        }
    }

    if (!GotExtension)
    {
        if ((RawDllName.Length + LdrApiDefaultExtension.Length + sizeof(UNICODE_NULL)) > sizeof(NameBuffer))
            return STATUS_NAME_TOO_LONG;
        RtlAppendUnicodeStringToString(&RawDllName, &LdrApiDefaultExtension);
    }

    __try {
        if (!LdrpCheckForLoadedDll(DllPath, &RawDllName, false, Redirected, &LdrEntry))
        {
            Status = LdrpMapDll(DllPath, RawDllName.Buffer, NameBuffer, DllCharacteristics, false, Redirected, &LdrEntry);
            if (!NT_SUCCESS(Status))
                __leave;

            if (DllCharacteristics && (*DllCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
            {
                LdrEntry->EntryPoint = nullptr;
                LdrEntry->Flags &= ~LDRP_IMAGE_DLL;
            }

            if (LdrEntry->Flags & LDRP_IMAGE_DLL)
            {
                if (!(LdrEntry->Flags & LDRP_COR_IMAGE))
                    Status = LdrpWalkImportDescriptor(DllPath, LdrEntry);

                if (LdrEntry->ObsoleteLoadCount != 0xFFFF)
                    LdrEntry->ObsoleteLoadCount++;
                // LdrpUpdateLoadCount2(LdrEntry, LDRP_UPDATE_REFCOUNT);

                if (!NT_SUCCESS(Status))
                {
                    LdrEntry->EntryPoint = nullptr;
                    InsertTailList(&Peb->Ldr->InInitializationOrderModuleList,
                                   &LdrEntry->InInitializationOrderLinks);
                    LdrpClearLoadInProgress();
                    LdrUnloadDll(LdrEntry->DllBase);
                    __leave;
                }
            }
            else if (LdrEntry->ObsoleteLoadCount != 0xFFFF)
            {
                LdrEntry->ObsoleteLoadCount++;
            }

            InsertTailList(&Peb->Ldr->InInitializationOrderModuleList,
                           &LdrEntry->InInitializationOrderLinks);

            if (CallInit)
            {
                Status = LdrpRunInitializeRoutines(nullptr);
                if (!NT_SUCCESS(Status))
                {
                    LdrUnloadDll(LdrEntry->DllBase);
                }
            }
        }
        else
        {
            if ((LdrEntry->Flags & LDRP_IMAGE_DLL) && (LdrEntry->ObsoleteLoadCount != 0xFFFF))
            {
                LdrEntry->ObsoleteLoadCount++;
                // LdrpUpdateLoadCount2(LdrEntry, LDRP_UPDATE_REFCOUNT);
                LdrpClearLoadInProgress();
            }
            else if (LdrEntry->ObsoleteLoadCount != 0xFFFF)
            {
                LdrEntry->ObsoleteLoadCount++;
            }
        }
    }
    __finally {
    }

    if (NT_SUCCESS(Status))
        *BaseAddress = LdrEntry->DllBase;
    else
        *BaseAddress = nullptr;

    return Status;
}

NTSTATUS NTAPI LdrpSnapThunk(_In_ PVOID ExportBase, _In_ PVOID ImportBase, _In_ IMAGE_THUNK_DATA* OriginalThunk, _In_ _Out_ IMAGE_THUNK_DATA* Thunk, _In_ PIMAGE_EXPORT_DIRECTORY ExportDirectory, _In_ ULONG ExportSize, _In_ BOOLEAN Static, _In_ LPSTR DllName)
{
    BOOLEAN IsOrdinal;
    USHORT Ordinal;
    ULONG OriginalOrdinal = 0;
    PIMAGE_IMPORT_BY_NAME AddressOfData;
    PULONG NameTable;
    PUSHORT OrdinalTable;
    LPSTR ImportName = nullptr, DotPosition;
    USHORT Hint;
    NTSTATUS Status;
    ULONG_PTR HardErrorParameters[3];
    UNICODE_STRING HardErrorDllName, HardErrorEntryPointName;
    ANSI_STRING TempString;
    ULONG Mask;
    ULONG Response;
    PULONG AddressOfFunctions;
    UNICODE_STRING TempUString;
    ANSI_STRING ForwarderName;
    PANSI_STRING ForwardName;
    PVOID ForwarderHandle;
    ULONG ForwardOrdinal;
    
    if ((IsOrdinal = IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal)))
    {
        OriginalOrdinal = IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);
        Ordinal = (USHORT)(OriginalOrdinal - ExportDirectory->Base);
    }
    else
    {
        AddressOfData = (PIMAGE_IMPORT_BY_NAME)
                        ((ULONG_PTR)ImportBase +
                        ((ULONG_PTR)OriginalThunk->u1.AddressOfData & 0xffffffff));

        ImportName = (LPSTR)AddressOfData->Name;

        NameTable = (PULONG)((ULONG_PTR)ExportBase +
                            (ULONG_PTR)ExportDirectory->AddressOfNames);
        OrdinalTable = (PUSHORT)((ULONG_PTR)ExportBase +
                                (ULONG_PTR)ExportDirectory->AddressOfNameOrdinals);

        Hint = AddressOfData->Hint;

        if (((ULONG)Hint < ExportDirectory->NumberOfNames) &&
            (!strcmp(ImportName, ((LPSTR)((ULONG_PTR)ExportBase + NameTable[Hint])))))
        {
            Ordinal = OrdinalTable[Hint];
        }
        else
        {
            Ordinal = LdrpNameToOrdinal(ImportName, ExportDirectory->NumberOfNames, ExportBase, NameTable, OrdinalTable);
        }
    }

    if ((ULONG)Ordinal >= ExportDirectory->NumberOfFunctions)
    {
    FailurePath:
        if (Static)
        {
            UNICODE_STRING SnapTarget;
            PLDR_DATA_TABLE_ENTRY LdrEntry;

            RtlInitAnsiString(&TempString, DllName ? DllName : "Unknown");

            if (LdrpCheckForLoadedDllHandle(ImportBase, &LdrEntry))
                SnapTarget = LdrEntry->BaseDllName;
            else
                RtlInitUnicodeString(&SnapTarget, L"Unknown");

            RtlAnsiStringToUnicodeString(&HardErrorDllName, &TempString, true);

            HardErrorParameters[1] = (ULONG_PTR)&HardErrorDllName;
            Mask = 2;

            if (IsOrdinal)
            {
                HardErrorParameters[0] = OriginalOrdinal;
            }
            else
            {
                RtlInitAnsiString(&TempString, ImportName);
                RtlAnsiStringToUnicodeString(&HardErrorEntryPointName,
                                            &TempString,
                                            true);

                HardErrorParameters[0] = (ULONG_PTR)&HardErrorEntryPointName;
                Mask = 3;
            }

            NtRaiseHardError(IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND, 2, Mask, HardErrorParameters, OptionOk, &Response);

            RtlFreeUnicodeString(&HardErrorDllName);
            if (!IsOrdinal)
            {
                RtlFreeUnicodeString(&HardErrorEntryPointName);
                RtlRaiseStatus(STATUS_ENTRYPOINT_NOT_FOUND);
            }

            RtlRaiseStatus(STATUS_ORDINAL_NOT_FOUND);
        }

        Thunk->u1.Function = (ULONG_PTR)0xffbadd11;

        Status = IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND;
    }
    else
    {
        AddressOfFunctions = (PULONG)
                            ((ULONG_PTR)ExportBase +
                            (ULONG_PTR)ExportDirectory->AddressOfFunctions);

        Thunk->u1.Function = (ULONG_PTR)ExportBase + AddressOfFunctions[Ordinal];

        if ((Thunk->u1.Function > (ULONG_PTR)ExportDirectory) &&
            (Thunk->u1.Function < ((ULONG_PTR)ExportDirectory + ExportSize)))
        {
            ImportName = (LPSTR)Thunk->u1.Function;

            DotPosition = strchr(ImportName, '.');

            if (!DotPosition)
                goto FailurePath;

            ForwarderName.Buffer = ImportName;
            ForwarderName.Length = (USHORT)(DotPosition - ImportName);
            ForwarderName.MaximumLength = ForwarderName.Length;
            Status = RtlAnsiStringToUnicodeString(&TempUString, &ForwarderName, true);

            if (NT_SUCCESS(Status))
            {
                WCHAR StringBuffer[MAX_PATH];
                UNICODE_STRING StaticString, *RedirectedImportName;
                BOOLEAN Redirected = false;

                RtlInitEmptyUnicodeString(&StaticString, StringBuffer, sizeof(StringBuffer));

                Status = LdrpApplyFileNameRedirection(&TempUString, &LdrApiDefaultExtension, &StaticString, nullptr, &RedirectedImportName, &Redirected);

                if (!NT_SUCCESS(Status) && Redirected)
                {
                    RedirectedImportName = &TempUString;
                }

                Status = LdrpLoadDll(Redirected, nullptr, nullptr, RedirectedImportName, &ForwarderHandle, false);

                RtlFreeUnicodeString(&TempUString);
            }

            if (!NT_SUCCESS(Status)) goto FailurePath;

            RtlInitAnsiString(&ForwarderName,
                            ImportName + ForwarderName.Length + sizeof(CHAR));

            if ((ForwarderName.Length > 1) && (*ForwarderName.Buffer == '#'))
            {
                ForwardName = nullptr;

                Status = RtlCharToInteger(ForwarderName.Buffer + sizeof(CHAR), 0, &ForwardOrdinal);

                if (!NT_SUCCESS(Status)) goto FailurePath;
            }
            else
            {
                ForwardName = &ForwarderName;
                ForwardOrdinal = 0;
            }

            Status = LdrpGetProcedureAddress(ForwarderHandle, ForwardName, ForwardOrdinal, (PVOID*)&Thunk->u1.Function, false);
                                            
            if (!NT_SUCCESS(Status)) goto FailurePath;
        }
        else
        {
            if (!AddressOfFunctions[Ordinal]) goto FailurePath;
        }

        Status = 0;
    }

    return Status;
}

NTSTATUS NTAPI LdrpGetProcedureAddress(_In_ PVOID BaseAddress, _In_opt_ PANSI_STRING Name, _In_opt_ ULONG Ordinal, _Out_ PVOID* ProcedureAddress, BOOLEAN ExecuteInit)
{
    NTSTATUS Status = 0;
    UCHAR ImportBuffer[64];
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    IMAGE_THUNK_DATA Thunk;
    PVOID ImageBase;
    PIMAGE_IMPORT_BY_NAME ImportName = nullptr;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG ExportDirSize, Length;
    PLIST_ENTRY Entry;

    if (Name)
    {
        Length = Name->Length +
                 sizeof(CHAR) +
                 FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);
        if (Length > UNICODE_STRING_MAX_BYTES)
        {
            return STATUS_NAME_TOO_LONG;
        }
 
        if (Length > sizeof(ImportBuffer))
        {
            ImportName = __bootstrap_malloc(Length);
            if (!ImportName)
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
        else
        {
            ImportName = (PIMAGE_IMPORT_BY_NAME)ImportBuffer;
        }
 
        ImportName->Hint = 0;
 
        memcpy(ImportName->Name, Name->Buffer, Name->Length);
        ImportName->Name[Name->Length] = ANSI_NULL;
 
        ImageBase = ImportName;
        Thunk.u1.AddressOfData = 0;
    }
    else
    {
        ImageBase = nullptr;
 
        if (!Ordinal)
        {
            return STATUS_INVALID_PARAMETER;
        }
 
        Thunk.u1.Ordinal = Ordinal | IMAGE_ORDINAL_FLAG;
    }
 
    __try {
        if (!LdrpCheckForLoadedDllHandle(BaseAddress, &LdrEntry))
        {
            Status = STATUS_DLL_NOT_FOUND;
            __leave;
        }

        ExportDir = RtlImageDirectoryEntryToData(LdrEntry->DllBase, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirSize);

        if (!ExportDir)
        {
            Status = STATUS_PROCEDURE_NOT_FOUND;
            __leave;
        }

        Status = LdrpSnapThunk(LdrEntry->DllBase, ImageBase, &Thunk, &Thunk, ExportDir, ExportDirSize, false, nullptr);
        
        if ((NT_SUCCESS(Status)) && (ExecuteInit))
        {
            Entry = NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Blink;
            LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
    
            if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED))
            {
                PEXCEPTION_POINTERS excinfo;
                __try
                {
                    Status = LdrpRunInitializeRoutines(nullptr);
                }
                __except(excinfo = _exception_info(), EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = excinfo->ExceptionRecord->ExceptionCode;
                }
            }
        }
    
        if (NT_SUCCESS(Status))
        {
            *ProcedureAddress = (PVOID)Thunk.u1.Function;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* ignore exception according to reactos */
    }

    if (ImportName && (ImportName != (PIMAGE_IMPORT_BY_NAME)ImportBuffer))
    {
        __bootstrap_free(ImportName);
    }
 
    return Status;
}

NTSTATUS NTAPI LdrGetProcedureAddress(_In_ PVOID BaseAddress, _In_opt_ PANSI_STRING Name, _In_opt_ ULONG Ordinal, _Out_ PVOID* ProcedureAddress)
{
    return LdrpGetProcedureAddress(BaseAddress, Name, Ordinal, ProcedureAddress, true);
}