#ifndef WINDOWS_H
#define WINDOWS_H

#ifdef __cplusplus
extern "C" {
#endif

struct _KUSER_SHARED_DATA;

#define USER_SHARED_DATA ((struct _KUSER_SHARED_DATA * const)0x7ffe0000)
#define CONTAINING_RECORD(address, type, field) ((type *)((char *)(address) - __builtin_offsetof(type, field)))
#define PtrToUlong(u) ((ULONG)(ULONGLONG)((PVOID)(u)))
#define HIWORD(l) ((WORD)(((ULONGLONG)(l)>>16)&0xFFFF))
#define LDR_IS_DATAFILE(handle) (((ULONG_PTR)(handle)) & (ULONG_PTR)1)
#define FIELD_OFFSET(Type, Field) ((LONG)__builtin_offsetof(Type, Field))
#define IMAGE_FIRST_SECTION( NtHeader ) ((IMAGE_SECTION_HEADER*) ((ULONG_PTR)(NtHeader) + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) + ((NtHeader))->FileHeader.SizeOfOptionalHeader))
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }
#define RTL_NUMBER_OF(x) (sizeof(x) / sizeof(x[0]))
#define RTL_FIELD_SIZE(type,field) (sizeof(((type *)0)->field))
#define RTL_SIZEOF_THROUGH_FIELD(type,field) (FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field))

#define __forceinline extern __inline__ __attribute__((__always_inline__,__gnu_inline__))

#define WINAPI __stdcall
#define NTAPI __stdcall

#ifdef _WIN64
    __forceinline struct _PEB* NtCurrentPeb() {
        struct _PEB* peb;
        __asm__("movq %%gs:0x60, %0" : "=r"(peb));
        return peb;
    }
    __forceinline struct _TEB* NtCurrentTeb() {
        struct _TEB* teb;
        __asm__("movq %%gs:0x30, %0" : "=r"(teb));
        return teb;
    }
#elif defined(_M_IX86)
    __forceinline struct _PEB* NtCurrentPeb() {
        struct _PEB* peb;
        __asm__("movl %%fs:0x30, %0" : "=r"(peb));
        return peb;
    }
    __forceinline struct _TEB* NtCurrentTeb() {
        struct _TEB* teb;
        __asm__("movl %%fs:0x18, %0" : "=r"(teb));
        return teb;
    }
#else
    #error "Unsupported architecture"
#endif


typedef void                    VOID;
typedef unsigned char           BYTE;
typedef unsigned short          WORD;
typedef unsigned long           DWORD;
typedef long                    LONG;
typedef int                     BOOL;
typedef unsigned int            UINT;
typedef char                    CHAR;
typedef unsigned char           UCHAR;

typedef unsigned short          USHORT;
typedef unsigned long           ULONG;
typedef long long               LONGLONG;
typedef unsigned long long      UINT64;
typedef unsigned long long      ULONGLONG;
typedef ULONGLONG               DWORD64;
typedef ULONGLONG               QWORD;
typedef ULONGLONG               ULONG64;

typedef void*                   PVOID;
typedef const void*             PCVOID;
typedef PVOID                   HANDLE;
typedef char*                   LPSTR;
typedef char*                   PCHAR;
typedef const char*             LPCSTR;
typedef __WCHAR_TYPE__          WCHAR;
typedef WCHAR*                  LPWSTR;
typedef const WCHAR*            LPCWSTR;
typedef WCHAR*                  PWCHAR;
typedef WCHAR*                  PWSTR;
typedef ULONGLONG               ULONG_PTR;
typedef LONG*                   LONG_PTR;
typedef unsigned char*          PBOOLEAN;
typedef const char*             PCSTR;
typedef LONGLONG*               PLONGLONG;
typedef ULONGLONG*              PULONGLONG;
typedef ULONG*                  PULONG;
typedef USHORT*                 PUSHORT;
typedef ULONGLONG*              PSIZE_T;
typedef const __WCHAR_TYPE__*   PCWSTR;
typedef const __WCHAR_TYPE__*   PCWCHAR;
typedef __WCHAR_TYPE__*         PWCH;
typedef const char*             PCSZ;
typedef DWORD                   DWORD_PTR;
typedef ULONGLONG*              PULONG_PTR;

typedef unsigned char           BOOLEAN;

typedef LONG                    NTSTATUS;
typedef DWORD                   LCID;
typedef ULONGLONG               SIZE_T;
typedef DWORD                   ACCESS_MASK;
typedef ACCESS_MASK*            PACCESS_MASK;

typedef HANDLE                  HMODULE;
typedef HANDLE                  HINSTANCE;
typedef HANDLE                  HLOCAL;
typedef HANDLE                  HGLOBAL;
typedef HANDLE                  HRSRC;
typedef HANDLE*                 PHANDLE;

typedef int(* FARPROC) ();

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) != 0)
#define NtCurrentProcess() 	   ( (HANDLE)(LONG_PTR)-1 )
#define NtCurrentThread() 	   ( (HANDLE)(LONG_PTR)-2 )
#define ZwCurrentProcess() 	   NtCurrentProcess()
#define ZwCurrentThread() 	   NtCurrentThread()
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = nullptr; \
}
#endif

#define _In_ 
#define _Inout_
#define _In_opt_
#define _Out_
#define GDI_BATCH_BUFFER_SIZE 310
#define UNICODE_NULL L'\0'
#define ANSI_NULL '\0'
#define WIN32_CLIENT_INFO_LENGTH 62
#define STATIC_UNICODE_BUFFER_LENGTH 261
#define TLS_MINIMUM_AVAILABLE 64
#define PROCESSOR_FEATURE_MAX 64
#define RTL_MAX_DRIVE_LETTERS 32
#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#define RESTART_MAX_CMD_LINE 1024
#define MAX_PATH 260
#define ANYSIZE_ARRAY 1
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define EXCEPTION_EXECUTE_HANDLER    1
#define EXCEPTION_CONTINUE_SEARCH    0
#define EXCEPTION_CONTINUE_EXECUTION -1
#define USHRT_MAX   0xffff
#define MAXUSHORT   (ULONG_PTR)USHRT_MAX
#define ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION 2

#define DLL_PROCESS_ATTACH   1
#define DLL_PROCESS_DETACH   0
#define DLL_THREAD_ATTACH   2
#define DLL_THREAD_DETACH   3

#define LDRP_PROCESS_ATTACH_CALLED   0x00080000

#define EXCEPTION_NONCONTINUABLE     0x1                    // The exception cannot be resumed
#define EXCEPTION_UNWINDING          0x2                    // Unwinding stack
#define EXCEPTION_EXIT_UNWIND        0x4                    // Unwinding due to thread/process exit
#define EXCEPTION_STACK_INVALID      0x8                    // Stack is in an invalid state
#define EXCEPTION_NESTED_CALL        0x10                   // Exception happened in a nested handler
#define EXCEPTION_TARGET_UNWIND      0x20                   // Targeting a specific handler
#define EXCEPTION_COLLIDED_UNWIND    0x40                   // A collision occurred in the unwind process
#define EXCEPTION_SOFTWARE_EXCEPTION 0xE0000000             // Used for user-defined exceptions

#define EXCEPTION_ACCESS_VIOLATION          0xC0000005      // Invalid memory access
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     0xC000008C      // Array bounds exceeded
#define EXCEPTION_BREAKPOINT                0x80000003      // Breakpoint encountered
#define EXCEPTION_DATATYPE_MISALIGNMENT     0x80000002      // Misaligned memory access
#define EXCEPTION_FLT_DENORMAL_OPERAND      0xC000008D      // Denormal floating-point operand
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        0xC000008E      // Float division by zero
#define EXCEPTION_FLT_INEXACT_RESULT        0xC000008F      // Float precision loss
#define EXCEPTION_FLT_INVALID_OPERATION     0xC0000090      // Invalid float operation
#define EXCEPTION_FLT_OVERFLOW              0xC0000091      // Float overflow
#define EXCEPTION_FLT_STACK_CHECK           0xC0000092      // Stack overflow in FPU
#define EXCEPTION_FLT_UNDERFLOW             0xC0000093      // Float underflow
#define EXCEPTION_ILLEGAL_INSTRUCTION       0xC000001D      // Invalid CPU instruction
#define EXCEPTION_IN_PAGE_ERROR             0xC0000006      // Page file error
#define EXCEPTION_INT_DIVIDE_BY_ZERO        0xC0000094      // Integer division by zero
#define EXCEPTION_INT_OVERFLOW              0xC0000095      // Integer overflow
#define EXCEPTION_INVALID_DISPOSITION       0xC0000026      // Invalid EXCEPTION_DISPOSITION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  0xC0000025      // Non-continuable exception
#define EXCEPTION_PRIV_INSTRUCTION          0xC0000096      // Privileged instruction
#define EXCEPTION_SINGLE_STEP               0x80000004      // Debug single-step trap
#define EXCEPTION_STACK_OVERFLOW            0xC00000FD      // Stack overflow

#define IMAGE_FILE_EXECUTABLE_IMAGE   0x0002
#define LDRP_IMAGE_DLL   0x00000004
#define LDRP_COR_IMAGE   0x00400000
#define LDRP_UPDATE_REFCOUNT   0x01 
#define LDRP_UPDATE_DEREFCOUNT   0x02
#define LDRP_LOAD_IN_PROGRESS   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS   0x00002000
#define LDRP_UPDATE_PIN   0x03
#define OBJ_CASE_INSENSITIVE   0x00000040L

#define GENERIC_ALL 0x10000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_WRITE 0x40000000
#define GENERIC_READ 0x80000000

#define FILE_SHARE_DELETE 0x00000004
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002

#define SECTION_MAP_READ   4
#define SECTION_MAP_EXECUTE   0x0008
#define SECTION_MAP_WRITE   0x0002

#define PAGE_READONLY   0x0002
#define PAGE_READWRITE   0x04
#define PAGE_EXECUTE   0x10

#define SEC_COMMIT   0x8000000
#define IMAGE_FILE_DLL   0x2000

#define REG_DWORD   4
#define REG_QWORD   11
#define REG_SZ   1

#define TAG_USTR   'RTSU'
#define OBJ_NAME_PATH_SEPARATOR   ((WCHAR)L'\\')
#define RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL 1
#define LDRP_ENTRY_PROCESSED   0x00004000

#define SYNCHRONIZE   (0x00100000L)
#define FILE_EXECUTE   ( 0x0020 )
#define FILE_NON_DIRECTORY_FILE   0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020

#define STATUS_NAME_TOO_LONG   ((NTSTATUS)0xC0000106)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define STATUS_INVALID_PARAMETER   ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_PATH_SYNTAX_BAD   ((NTSTATUS)0xC000003B)
#define STATUS_INVALID_IMAGE_FORMAT   ((NTSTATUS)0xC000007B)
#define STATUS_NO_MEMORY   ((NTSTATUS)(0xC0000017L))
#define STATUS_ORDINAL_NOT_FOUND   ((NTSTATUS)0xC0000138)
#define STATUS_ENTRYPOINT_NOT_FOUND   ((NTSTATUS)0xC0000139)
#define STATUS_DLL_NOT_FOUND   ((NTSTATUS)0xC0000135)
#define STATUS_PROCEDURE_NOT_FOUND   ((NTSTATUS)0xC000007A)
#define STATUS_SXS_KEY_NOT_FOUND   ((NTSTATUS)0xC0150008)
#define STATUS_ACCESS_VIOLATION   ((NTSTATUS)0xC0000005)
#define STATUS_DLL_INIT_FAILED   ((NTSTATUS)0xC0000142)
#define STATUS_SHARING_VIOLATION   ((NTSTATUS)0xC0000043L)
#define STATUS_ACCESS_DENIED   ((NTSTATUS)0xC0000022L)
#define STATUS_SXS_SECTION_NOT_FOUND ((NTSTATUS)0xC0150006)
#define STATUS_OBJECT_NAME_NOT_FOUND   ((NTSTATUS)0xC0000034L)

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK   0x00000001

#define NTSYSAPI __declspec(dllimport)

#define MAXIMUM_LEADBYTES 12
#define DEFAULT_SECURITY_COOKIE   0xBB40E64E
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   10
#define UNICODE_STRING_MAX_BYTES   ((USHORT) 65534)

#define _WIN32_WINNT_VISTA   0x0600
#define _WIN32_WINNT_WIN10   0x0A00
#define _WIN32_WINNT_WIN2K   0x0500
#define _WIN32_WINNT_WIN6   0x0600
#define _WIN32_WINNT_WIN7   0x0601
#define _WIN32_WINNT_WIN8   0x0602
#define _WIN32_WINNT_WINBLUE   0x0603

#define APISET_WIN7   (1 << 0)
#define APISET_WIN8   (1 << 1)
#define APISET_WIN81   (1 << 2)
#define APISET_WIN10   (1 << 3)

#ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#else
#define SWAPD(x) x
#define SWAPW(x) x
#endif
#define SD(Object,Field) Object->Field = SWAPD(Object->Field)
#define SW(Object,Field) Object->Field = SWAPW(Object->Field)

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32 0x80000000

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _EXCEPTION_DISPOSITION
{
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION; 

typedef struct _M128A
{
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A; 

typedef struct _XSAVE_FORMAT
{
    USHORT ControlWord;
    USHORT StatusWord;
    UCHAR TagWord;
    UCHAR Reserved1;
    USHORT ErrorOpcode;
    ULONG ErrorOffset;
    USHORT ErrorSelector;
    USHORT Reserved2;
    ULONG DataOffset;
    USHORT DataSelector;
    USHORT Reserved3;
    ULONG MxCsr;
    ULONG MxCsr_Mask;
    struct _M128A FloatRegisters[8];
    struct _M128A XmmRegisters[16];
    UCHAR Reserved4[96];
} XSAVE_FORMAT, *PXSAVE_FORMAT; 

typedef struct _CONTEXT
{
    ULONGLONG P1Home;
    ULONGLONG P2Home;
    ULONGLONG P3Home;
    ULONGLONG P4Home;
    ULONGLONG P5Home;
    ULONGLONG P6Home;
    ULONG ContextFlags;
    ULONG MxCsr;
    USHORT SegCs;
    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;
    USHORT SegSs;
    ULONG EFlags;
    ULONGLONG Dr0;
    ULONGLONG Dr1;
    ULONGLONG Dr2;
    ULONGLONG Dr3;
    ULONGLONG Dr6;
    ULONGLONG Dr7;
    ULONGLONG Rax;
    ULONGLONG Rcx;
    ULONGLONG Rdx;
    ULONGLONG Rbx;
    ULONGLONG Rsp;
    ULONGLONG Rbp;
    ULONGLONG Rsi;
    ULONGLONG Rdi;
    ULONGLONG R8;
    ULONGLONG R9;
    ULONGLONG R10;
    ULONGLONG R11;
    ULONGLONG R12;
    ULONGLONG R13;
    ULONGLONG R14;
    ULONGLONG R15;
    ULONGLONG Rip;
    union
    {
        struct _XSAVE_FORMAT FltSave;
        struct
        {
            struct _M128A Header[2];
            struct _M128A Legacy[8];
            struct _M128A Xmm0;
            struct _M128A Xmm1;
            struct _M128A Xmm2;
            struct _M128A Xmm3;
            struct _M128A Xmm4;
            struct _M128A Xmm5;
            struct _M128A Xmm6;
            struct _M128A Xmm7;
            struct _M128A Xmm8;
            struct _M128A Xmm9;
            struct _M128A Xmm10;
            struct _M128A Xmm11;
            struct _M128A Xmm12;
            struct _M128A Xmm13;
            struct _M128A Xmm14;
            struct _M128A Xmm15;
        };
    };
    struct _M128A VectorRegister[26];
    ULONGLONG VectorControl;
    ULONGLONG DebugControl;
    ULONGLONG LastBranchToRip;
    ULONGLONG LastBranchFromRip;
    ULONGLONG LastExceptionToRip;
    ULONGLONG LastExceptionFromRip;
} CONTEXT, *PCONTEXT; 

typedef struct _EXCEPTION_RECORD
{
    LONG ExceptionCode;
    ULONG ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    VOID* ExceptionAddress;
    ULONG NumberParameters;
    ULONGLONG ExceptionInformation[15];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD; 

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

typedef struct _EXCEPTION_REGISTRATION_RECORD
{
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    enum _EXCEPTION_DISPOSITION (*Handler)(struct _EXCEPTION_RECORD* arg1, VOID* arg2, struct _CONTEXT* arg3, VOID* arg4);
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD; 

typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        DWORD Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB, *PNT_TIB;

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;
    ULONG ExtendedTocOffset;
    ULONG AssemblyRosterOffset;
    ULONG Flags;
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

struct _ACTIVATION_CONTEXT;

typedef VOID (NTAPI *PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType,
    _In_ struct _ACTIVATION_CONTEXT* ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );

typedef BOOLEAN NTAPI LDR_INIT_ROUTINE(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
    );

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;

typedef struct _PROCESSOR_NUMBER {
    USHORT Group;
    UCHAR  Number;
    UCHAR  Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

#ifdef _WIN64
    typedef ULONGLONG KAFFINITY;
#else 
    typedef ULONG KAFFINITY;
#endif

typedef struct _GROUP_AFFINITY {
    KAFFINITY Mask;
    WORD Group;
    WORD Reserved[3];
} GROUP_AFFINITY, *PGROUP_AFFINITY;

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE, *PALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _XSTATE_FEATURE {
    ULONG Offset;
    ULONG Size;
} XSTATE_FEATURE, *PXSTATE_FEATURE;

typedef struct _XSTATE_CONFIGURATION {
    ULONG64 EnabledFeatures;            /* bitmask of enabled processor features (e.g., AVX, SSE) */
    ULONG64 EnabledVolatileFeatures;    /* Features that are volatile (cleared on context switch) */
    ULONG Size;                         /* Total size of extended state save area */
    union {
        ULONG ControlFlags;
        struct {
            ULONG OptimizedSave : 1;
            ULONG CompactionEnabled : 1;
            ULONG Reserved : 30;
        };
    };
    XSTATE_FEATURE Features[64];
    ULONG64 EnabledSupervisorFeatures;
    ULONG64 AlignedFeatures;
    ULONG64 AllFeatureSize;
    ULONG64 AllFeatures;
    ULONG64 EnabledUserVisibleSupervisorFeatures;
} XSTATE_CONFIGURATION, *PXSTATE_CONFIGURATION;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef LDR_INIT_ROUTINE* PLDR_INIT_ROUTINE;

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD *Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef struct _LDRP_LOAD_CONTEXT *PLDRP_LOAD_CONTEXT;

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    } DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary,
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, *PLDR_HOT_PATCH_STATE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    PLDRP_LOAD_CONTEXT LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    PVOID OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel;
    ULONG CheckSum;
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct {
    ULONG Size;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG GlobalFlagsClear;
    ULONG GlobalFlagsSet;
    ULONG CriticalSectionDefaultTimeout;
    ULONG DeCommitFreeBlockThreshold;
    ULONG DeCommitTotalFreeThreshold;
    ULONG LockPrefixTable;
    ULONG MaximumAllocationSize;
    ULONG VirtualMemoryThreshold;
    ULONG ProcessHeapFlags;
    ULONG ProcessAffinityMask;
    USHORT CSDVersion;
    USHORT Reserved1;
    ULONG EditList;
    ULONG SecurityCookie;
    ULONG SEHandlerTable;
    ULONG SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct {
    ULONG Size;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG GlobalFlagsClear;
    ULONG GlobalFlagsSet;
    ULONG CriticalSectionDefaultTimeout;
    ULONGLONG DeCommitFreeBlockThreshold;
    ULONGLONG DeCommitTotalFreeThreshold;
    ULONGLONG LockPrefixTable;
    ULONGLONG MaximumAllocationSize;
    ULONGLONG VirtualMemoryThreshold;
    ULONGLONG ProcessAffinityMask;
    ULONG ProcessHeapFlags;
    USHORT CSDVersion;
    USHORT Reserved1;
    ULONGLONG EditList;
    ULONGLONG SecurityCookie;
    ULONGLONG SEHandlerTable;
    ULONGLONG SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;
   
#ifdef _WIN64
typedef IMAGE_LOAD_CONFIG_DIRECTORY64     IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY64    PIMAGE_LOAD_CONFIG_DIRECTORY;
#else
typedef IMAGE_LOAD_CONFIG_DIRECTORY32     IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY32    PIMAGE_LOAD_CONFIG_DIRECTORY;
#endif

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _RTLP_CURDIR_REF
{
    LONG RefCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown,
    RtlPathTypeUncAbsolute,
    RtlPathTypeDriveAbsolute,
    RtlPathTypeDriveRelative,
    RtlPathTypeRooted,
    RtlPathTypeRelative,
    RtlPathTypeLocalDevice,
    RtlPathTypeRootLocalDevice,
} RTL_PATH_TYPE;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions, // HANDLE
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority, // q: ULONG
    ProcessSchedulerSharedData, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
    ProcessEnclaveAddressSpaceRestriction, // since 25H2
    ProcessAvailableCpus,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // NtQuerySystemInformationEx // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation, // SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation, // CRITICAL_PROCESS_EXCEPTION_DATA
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150 // (requires SeTcbPrivilege)
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation, // NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation, // NtQuerySystemInformationEx
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation, // NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation, // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
    SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation, // NtQuerySystemInformationEx
    SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation, // SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation, // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation, // SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation, // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx, // SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout, // ULONG
    SystemBreakOnContextUnwindFailureInformation, // ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation, // SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation, // since 25H2
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

enum
{
    UNW_FLAG_NHANDLER  = 0x00,
    UNW_FLAG_EHANDLER  = 0x01,
    UNW_FLAG_UHANDLER  = 0x02,
    UNW_FLAG_CHAININFO = 0x04
};

typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef struct _IMAGE_IMPORT_BY_NAME
{
    WORD Hint;
    BYTE Name[1];
}
IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        ULONG ForwarderString;
        ULONG Function;
        ULONG Ordinal;
        ULONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;
   
typedef struct _IMAGE_TLS_DIRECTORY32 {
    ULONG StartAddressOfRawData;
    ULONG EndAddressOfRawData;
    ULONG AddressOfIndex;
    ULONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)

#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define CONTEXT_i386    0x00010000
#define CONTEXT_i486    0x00010000

#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
 
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef IMAGE_TLS_DIRECTORY64           IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64          PIMAGE_TLS_DIRECTORY;
#else
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef IMAGE_TLS_DIRECTORY32           IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32          PIMAGE_TLS_DIRECTORY;
#endif

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    ULONG EntryCount;
    ULONG ContentionCount;
    ULONG Flags;
    USHORT CreatorBackTraceIndexHigh;
    USHORT Identifier;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

#pragma pack(push, 8)
typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    SIZE_T SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#pragma pack(pop)

typedef LONG (WINAPI *PVECTORED_EXCEPTION_HANDLER)(
    _In_ struct _EXCEPTION_POINTERS* ExceptionInfo
);

typedef struct _SLIST_HEADER
{
     union
     {
          UINT64 Alignment;
          struct
          {
               SINGLE_LIST_ENTRY Next;
               WORD Depth;
               WORD Sequence;
          };
     };
} SLIST_HEADER, *PSLIST_HEADER;

typedef struct _KERNEL_CALLBACK_TABLE
{
    PVOID __fnCOPYDATA;
    PVOID __fnCOPYGLOBALDATA;
    PVOID __fnEMPTY1;
    PVOID __fnNCDESTROY;
    PVOID __fnDWORDOPTINLPMSG;
    PVOID __fnINOUTDRAG;
    PVOID __fnGETTEXTLENGTHS1;
    PVOID __fnINCNTOUTSTRING;
    PVOID __fnINCNTOUTSTRINGNULL;
    PVOID __fnINLPCOMPAREITEMSTRUCT;
    PVOID __fnINLPCREATESTRUCT;
    PVOID __fnINLPDELETEITEMSTRUCT;
    PVOID __fnINLPDRAWITEMSTRUCT;
    PVOID __fnPOPTINLPUINT1;
    PVOID __fnPOPTINLPUINT2;
    PVOID __fnINLPMDICREATESTRUCT;
    PVOID __fnINOUTLPMEASUREITEMSTRUCT;
    PVOID __fnINLPWINDOWPOS;
    PVOID __fnINOUTLPPOINT51;
    PVOID __fnINOUTLPSCROLLINFO;
    PVOID __fnINOUTLPRECT;
    PVOID __fnINOUTNCCALCSIZE;
    PVOID __fnINOUTLPPOINT52;
    PVOID __fnINPAINTCLIPBRD;
    PVOID __fnINSIZECLIPBRD;
    PVOID __fnINDESTROYCLIPBRD;
    PVOID __fnINSTRINGNULL1;
    PVOID __fnINSTRINGNULL2;
    PVOID __fnINDEVICECHANGE;
    PVOID __fnPOWERBROADCAST;
    PVOID __fnINLPUAHDRAWMENU1;
    PVOID __fnOPTOUTLPDWORDOPTOUTLPDWORD1;
    PVOID __fnOPTOUTLPDWORDOPTOUTLPDWORD2;
    PVOID __fnOUTDWORDINDWORD;
    PVOID __fnOUTLPRECT;
    PVOID __fnOUTSTRING;
    PVOID __fnPOPTINLPUINT3;
    PVOID __fnPOUTLPINT;
    PVOID __fnSENTDDEMSG;
    PVOID __fnINOUTSTYLECHANGE1;
    PVOID __fnHkINDWORD;
    PVOID __fnHkINLPCBTACTIVATESTRUCT;
    PVOID __fnHkINLPCBTCREATESTRUCT;
    PVOID __fnHkINLPDEBUGHOOKSTRUCT;
    PVOID __fnHkINLPMOUSEHOOKSTRUCTEX1;
    PVOID __fnHkINLPKBDLLHOOKSTRUCT;
    PVOID __fnHkINLPMSLLHOOKSTRUCT;
    PVOID __fnHkINLPMSG;
    PVOID __fnHkINLPRECT;
    PVOID __fnHkOPTINLPEVENTMSG;
    PVOID __xxxClientCallDelegateThread;
    PVOID __ClientCallDummyCallback1;
    PVOID __ClientCallDummyCallback2;
    PVOID __fnSHELLWINDOWMANAGEMENTCALLOUT;
    PVOID __fnSHELLWINDOWMANAGEMENTNOTIFY;
    PVOID __ClientCallDummyCallback3;
    PVOID __xxxClientCallDitThread;
    PVOID __xxxClientEnableMMCSS;
    PVOID __xxxClientUpdateDpi;
    PVOID __xxxClientExpandStringW;
    PVOID __ClientCopyDDEIn1;
    PVOID __ClientCopyDDEIn2;
    PVOID __ClientCopyDDEOut1;
    PVOID __ClientCopyDDEOut2;
    PVOID __ClientCopyImage;
    PVOID __ClientEventCallback;
    PVOID __ClientFindMnemChar;
    PVOID __ClientFreeDDEHandle;
    PVOID __ClientFreeLibrary;
    PVOID __ClientGetCharsetInfo;
    PVOID __ClientGetDDEFlags;
    PVOID __ClientGetDDEHookData;
    PVOID __ClientGetListboxString;
    PVOID __ClientGetMessageMPH;
    PVOID __ClientLoadImage;
    PVOID __ClientLoadLibrary;
    PVOID __ClientLoadMenu;
    PVOID __ClientLoadLocalT1Fonts;
    PVOID __ClientPSMTextOut;
    PVOID __ClientLpkDrawTextEx;
    PVOID __ClientExtTextOutW;
    PVOID __ClientGetTextExtentPointW;
    PVOID __ClientCharToWchar;
    PVOID __ClientAddFontResourceW;
    PVOID __ClientThreadSetup;
    PVOID __ClientDeliverUserApc;
    PVOID __ClientNoMemoryPopup;
    PVOID __ClientMonitorEnumProc;
    PVOID __ClientCallWinEventProc;
    PVOID __ClientWaitMessageExMPH;
    PVOID __ClientCallDummyCallback4;
    PVOID __ClientCallDummyCallback5;
    PVOID __ClientImmLoadLayout;
    PVOID __ClientImmProcessKey;
    PVOID __fnIMECONTROL;
    PVOID __fnINWPARAMDBCSCHAR;
    PVOID __fnGETTEXTLENGTHS2;
    PVOID __ClientCallDummyCallback6;
    PVOID __ClientLoadStringW;
    PVOID __ClientLoadOLE;
    PVOID __ClientRegisterDragDrop;
    PVOID __ClientRevokeDragDrop;
    PVOID __fnINOUTMENUGETOBJECT;
    PVOID __ClientPrinterThunk;
    PVOID __fnOUTLPCOMBOBOXINFO;
    PVOID __fnOUTLPSCROLLBARINFO;
    PVOID __fnINLPUAHDRAWMENU2;
    PVOID __fnINLPUAHDRAWMENUITEM;
    PVOID __fnINLPUAHDRAWMENU3;
    PVOID __fnINOUTLPUAHMEASUREMENUITEM;
    PVOID __fnINLPUAHDRAWMENU4;
    PVOID __fnOUTLPTITLEBARINFOEX;
    PVOID __fnTOUCH;
    PVOID __fnGESTURE;
    PVOID __fnPOPTINLPUINT4;
    PVOID __fnPOPTINLPUINT5;
    PVOID __xxxClientCallDefaultInputHandler;
    PVOID __fnEMPTY2;
    PVOID __ClientRimDevCallback;
    PVOID __xxxClientCallMinTouchHitTestingCallback;
    PVOID __ClientCallLocalMouseHooks;
    PVOID __xxxClientBroadcastThemeChange;
    PVOID __xxxClientCallDevCallbackSimple;
    PVOID __xxxClientAllocWindowClassExtraBytes;
    PVOID __xxxClientFreeWindowClassExtraBytes;
    PVOID __fnGETWINDOWDATA;
    PVOID __fnINOUTSTYLECHANGE2;
    PVOID __fnHkINLPMOUSEHOOKSTRUCTEX2;
    PVOID __xxxClientCallDefWindowProc;
    PVOID __fnSHELLSYNCDISPLAYCHANGED;
    PVOID __fnHkINLPCHARHOOKSTRUCT;
    PVOID __fnINTERCEPTEDWINDOWACTION;
    PVOID __xxxTooltipCallback;
    PVOID __xxxClientInitPSBInfo;
    PVOID __xxxClientDoScrollMenu;
    PVOID __xxxClientEndScroll;
    PVOID __xxxClientDrawSize;
    PVOID __xxxClientDrawScrollBar;
    PVOID __xxxClientHitTestScrollBar;
    PVOID __xxxClientTrackInit;
} KERNEL_CALLBACK_TABLE, *PKERNEL_CALLBACK_TABLE;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _API_SET_NAMESPACE
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _SILO_USER_SHARED_DATA
{
    ULONG ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForegroundProcessId;
    NT_PRODUCT_TYPE NtProductType;
    ULONG SuiteMask;
    ULONG SharedUserSessionId; // since RS2
    BOOLEAN IsMultiSessionSku;
    BOOLEAN IsStateSeparationEnabled;
    WCHAR NtSystemRoot[260];
    USHORT UserModeGlobalLogger[16];
    ULONG TimeZoneId; // since 21H2
    LONG TimeZoneBiasStamp;
    KSYSTEM_TIME TimeZoneBias;
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, *PSILO_USER_SHARED_DATA;

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef struct _CPTABLEINFO
{
    USHORT CodePage;
    USHORT MaximumCharacterSize;
    USHORT DefaultChar;
    USHORT UniDefaultChar;
    USHORT TransDefaultChar;
    USHORT TransUniDefaultChar;
    USHORT DBCSCodePage;
    UCHAR LeadByte[MAXIMUM_LEADBYTES];
    PUSHORT MultiByteTable;
    PVOID WideCharTable;
    PUSHORT DBCSRanges;
    PUSHORT DBCSOffsets;
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO
{
    CPTABLEINFO OemTableInfo;
    CPTABLEINFO AnsiTableInfo;
    PUSHORT UpperCaseTable;
    PUSHORT LowerCaseTable;
} NLSTABLEINFO, *PNLSTABLEINFO;

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(
    VOID
    );

typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _WER_RECOVERY_INFO
{
    ULONG Length;
    PVOID Callback;
    PVOID Parameter;
    HANDLE Started;
    HANDLE Finished;
    HANDLE InProgress;
    LONG LastError;
    BOOL Successful;
    ULONG PingInterval;
    ULONG Flags;
} WER_RECOVERY_INFO, *PWER_RECOVERY_INFO;

typedef struct _WER_FILE
{
    USHORT Flags;
    WCHAR Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

typedef struct _WER_MEMORY
{
    PVOID Address;
    ULONG Size;
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER
{
    PVOID Next;
    USHORT Flags;
    union
    {
        WER_FILE File;
        WER_MEMORY Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

typedef struct _WER_METADATA
{
    PVOID Next;
    WCHAR Key[64];
    WCHAR Value[128];
} WER_METADATA, *PWER_METADATA;

typedef struct _WER_RUNTIME_DLL
{
    PVOID Next;
    ULONG Length;
    PVOID Context;
    WCHAR CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

typedef struct _WER_DUMP_COLLECTION
{
    PVOID Next;
    ULONG ProcessId;
    ULONG ThreadId;
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_HEAP_MAIN_HEADER
{
    WCHAR Signature[16];
    LIST_ENTRY Links;
    HANDLE Mutex;
    PVOID FreeHeap;
    ULONG FreeCount;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

typedef struct _WER_PEB_HEADER_BLOCK
{
    LONG Length;
    WCHAR Signature[16];
    WCHAR AppDataRelativePath[64];
    WCHAR RestartCommandLine[RESTART_MAX_CMD_LINE];
    WER_RECOVERY_INFO RecoveryInfo;
    PWER_GATHER Gather;
    PWER_METADATA MetaData;
    PWER_RUNTIME_DLL RuntimeDll;
    PWER_DUMP_COLLECTION DumpCollection;
    LONG GatherCount;
    LONG MetaDataCount;
    LONG DumpCount;
    LONG Flags;
    WER_HEAP_MAIN_HEADER MainHeader;
    PVOID Reserved;
} WER_PEB_HEADER_BLOCK, *PWER_PEB_HEADER_BLOCK;

typedef struct _TELEMETRY_COVERAGE_HEADER
{
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    struct
    {
        USHORT TracingEnabled : 1;
        USHORT Reserved1 : 15;
    };
    ULONG HashTableEntries;
    ULONG HashIndexMask;
    ULONG TableUpdateVersion;
    ULONG TableSizeInBytes;
    ULONG LastResetTick;
    ULONG ResetRound;
    ULONG Reserved2;
    ULONG RecordedCount;
    ULONG Reserved3[4];
    ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, *PTELEMETRY_COVERAGE_HEADER;

typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED
{
    ULONG Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
    PVOID Extra1;
    PVOID Extra2;
    PVOID Extra3;
    PVOID Extra4;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;                // 64-bit
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;       // 64-bit
    ULONGLONG            SizeOfStackCommit;        // 64-bit
    ULONGLONG            SizeOfHeapReserve;        // 64-bit
    ULONGLONG            SizeOfHeapCommit;         // 64-bit
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#ifdef _WIN64
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
    typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
#else
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
#endif

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _LEAP_SECOND_DATA *PLEAP_SECOND_DATA;

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer; 
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle; /* handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation. */
    PVOID ThreadLocalStoragePointer;
    struct _PEB* Peb;
    ULONG LastErrorValue; /* previous Win32 error value for this thread */
    ULONG CountOfOwnedCriticalSections; /* number of critical sections owned by the process */
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[25];
    PVOID HeapFlsData; /* Teb->HasFiberData */

    ULONG_PTR RngState[4];
#else
    PVOID SystemReserved1[26];
#endif
    CHAR PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId; /* process ID (PID) that the current COM server thread is acting on behalf of */
    ACTIVATION_CONTEXT_STACK ActivationStack; /* https://en.wikipedia.org/wiki/Side-by-side_assembly shit */
    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode; /* the last exception status for the current thread. */
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp; /* SP of the current system call or exception during instrumentation. */
    ULONG_PTR InstrumentationCallbackPreviousPc; /* PC of the current system call or exception during instrumentation. */
    ULONG_PTR InstrumentationCallbackPreviousSp; /* SP of the previous system call or exception during instrumentation. */
#ifdef _WIN64
    ULONG TxFsContext; /* miniversion ID of the current transacted file operation. */
#endif
    BOOLEAN InstrumentationCallbackDisabled; /* state of the system call or exception instrumentation callback. */
#ifdef _WIN64
    BOOLEAN UnalignedLoadStoreExceptions; /* state of alignment exceptions for unaligned load/store operations. */
#endif
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    NTSTATUS LastStatusValue; /* previous status value for this thread */
    UNICODE_STRING StaticUnicodeString; /* static string for use by the application. */
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH]; /* static unicode buffer for use by application. */
    PVOID DeallocationStack; /* maximum stack size and indicates the base of the stack. */
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE]; /* data for tls (TlsGetValue) */
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorMode; /* error mode for the current thread. (GetThreadErrorMode) */
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;
    PVOID SubProcessTag; /* service creating the thread (svchost). */ // TODO Take a look at this, might be usefull
    PVOID PerflibData;
    PVOID EtwTraceData;
    HANDLE WinSockData; /* address of a socket handle during a blocking socket operation. (WSAStartup) */
    ULONG GdiBatchCount; /* number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit) */
    union /* preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx) */
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };
    ULONG GuaranteedStackBytes; /* minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee) */
    PVOID ReservedForPerf;
    PVOID ReservedForOle; /* tagSOleTlsData */
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID *TlsExpansionSlots;
#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo;
    PVOID Unused;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter;
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
    PVOID SchedulerSharedDataSlot;
    PVOID HeapWalkContext;
    GROUP_AFFINITY PrimaryGroupAffinity;
    ULONG Rcu[2];
} TEB, *PTEB;

typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    volatile KSYSTEM_TIME InterruptTime; /* 64-bit interrupt time in 100ns units. */
    volatile KSYSTEM_TIME SystemTime; /* 64-bit system time in 100ns units. */
    volatile KSYSTEM_TIME TimeZoneBias; /* 64-bit time zone bias. */

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    WCHAR NtSystemRoot[260]; /* MUST BE ACCESSED USING RtlGetNtSystemRoot OR INACCURATE */
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;

    ULONGLONG RNGSeedVersion; /* Kernel Root RNG state seed version */
    ULONG GlobalValidationRunlevel;
    volatile LONG TimeZoneBiasStamp;

    ULONG NtBuildNumber;
    NT_PRODUCT_TYPE NtProductType; /* MUST BE ACCESSED USING RtlGetNtProductType OR INACCURATE */
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG Reserved1;
    ULONG Reserved3;

    volatile ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    ULONG BootId; /* incremented for each boot attempt by the OS loader. */
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask; /* not accurate */
    BOOLEAN KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT CyclesPerYield; /* number of kernel measured cycles per yield */
    volatile ULONG ActiveConsoleId;
    volatile ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
#if defined(_ARM64_)
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
            UCHAR : 6;
        };
#endif
    };
    UCHAR Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent       : 1;
            ULONG DbgElevationEnabled       : 1;
            ULONG DbgVirtEnabled            : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled             : 1;
            ULONG DbgDynProcessorEnabled    : 1;
            ULONG DbgConsoleBrokerEnabled   : 1;
            ULONG DbgSecureBootEnabled      : 1;
            ULONG DbgMultiSessionSku        : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG DbgSplitTokenEnabled      : 1;
            ULONG DbgShadowAdminEnabled     : 1;
            ULONG SpareBits                 : 19;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;

    ULONG DataFlagsPad[1];

    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;
    ULONG SystemCall;
    ULONG Reserved2;

    ULONGLONG FullNumberOfPhysicalPages;
    ULONGLONG SystemCallPad[1];
    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG Cookie;
    ULONG CookiePad[1];
    LONGLONG ConsoleSessionForegroundProcessId;
    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;
    ULONG EnclaveFeatureMask[4];
    ULONG TelemetryCoverageRound;
    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;

    ULONGLONG Reserved4;
    volatile ULONGLONG InterruptTimeBias;
    volatile ULONGLONG QpcBias;
    ULONG ActiveProcessorCount;
    volatile UCHAR ActiveGroupCount;
    UCHAR Reserved9;
    union {
        USHORT QpcData;
        struct {
            volatile UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };

    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION XState;
    KSYSTEM_TIME FeatureConfigurationChangeStamp;
    ULONG Spare;
    ULONG64 UserPointerAuthMask;
#if defined(_ARM64_)
    XSTATE_CONFIGURATION XStateArm64;
#else
    ULONG Reserved10[210];
#endif
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace; /* process was cloned with an inherited address space. */
    BOOLEAN ReadImageFileExecOptions; /* process has image file execution options (IFEO). */
    BOOLEAN BeingDebugged; /* process has a debugger attached. */
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;            // The process uses large image regions (4 MB).
            BOOLEAN IsProtectedProcess : 1;             // The process is a protected process.
            BOOLEAN IsImageDynamicallyRelocated : 1;    // The process image base address was relocated.
            BOOLEAN SkipPatchingUser32Forwarders : 1;   // The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.
            BOOLEAN IsPackagedProcess : 1;              // The process is a packaged store process (APPX/MSIX).
            BOOLEAN IsAppContainer : 1;                 // The process has an AppContainer token.
            BOOLEAN IsProtectedProcessLight : 1;        // The process is a protected process (light).
            BOOLEAN IsLongPathAwareProcess : 1;         // The process is long path aware.
        };
    };
    HANDLE Mutant; /* mutex sync handle */
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap; /* pointer to the process default heap */
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr; 
    PVOID IFEOKey; /* Image File Execution Options key. */
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;                 // The process is part of a job.
            ULONG ProcessInitializing : 1;          // The process is initializing.
            ULONG ProcessUsingVEH : 1;              // The process is using VEH.
            ULONG ProcessUsingVCH : 1;              // The process is using VCH.
            ULONG ProcessUsingFTH : 1;              // The process is using FTH.
            ULONG ProcessPreviouslyThrottled : 1;   // The process was previously throttled.
            ULONG ProcessCurrentlyThrottled : 1;    // The process is currently throttled.
            ULONG ProcessImagesHotPatched : 1;      // The process images are hot patched. // RS5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32; /* Active Template Library (ATL) singly linked list (32-bit) */
    PAPI_SET_NAMESPACE ApiSetMap;
    ULONG TlsExpansionCounter;
    PRTL_BITMAP TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase; /* Used by CSRSS */
    PSILO_USER_SHARED_DATA SharedData; /* USER_SHARED_DATA for the current SILO. */
    PVOID* ReadOnlyStaticServerData; /* Used by CSRSS */
    PCPTABLEINFO AnsiCodePageData;
    PCPTABLEINFO OemCodePageData;
    PNLSTABLEINFO UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    union
    {
        ULONG NtGlobalFlag;
        struct
        {
            ULONG StopOnException : 1;          // FLG_STOP_ON_EXCEPTION
            ULONG ShowLoaderSnaps : 1;          // FLG_SHOW_LDR_SNAPS
            ULONG DebugInitialCommand : 1;      // FLG_DEBUG_INITIAL_COMMAND
            ULONG StopOnHungGUI : 1;            // FLG_STOP_ON_HUNG_GUI
            ULONG HeapEnableTailCheck : 1;      // FLG_HEAP_ENABLE_TAIL_CHECK
            ULONG HeapEnableFreeCheck : 1;      // FLG_HEAP_ENABLE_FREE_CHECK
            ULONG HeapValidateParameters : 1;   // FLG_HEAP_VALIDATE_PARAMETERS
            ULONG HeapValidateAll : 1;          // FLG_HEAP_VALIDATE_ALL
            ULONG ApplicationVerifier : 1;      // FLG_APPLICATION_VERIFIER
            ULONG MonitorSilentProcessExit : 1; // FLG_MONITOR_SILENT_PROCESS_EXIT
            ULONG PoolEnableTagging : 1;        // FLG_POOL_ENABLE_TAGGING
            ULONG HeapEnableTagging : 1;        // FLG_HEAP_ENABLE_TAGGING
            ULONG UserStackTraceDb : 1;         // FLG_USER_STACK_TRACE_DB
            ULONG KernelStackTraceDb : 1;       // FLG_KERNEL_STACK_TRACE_DB
            ULONG MaintainObjectTypeList : 1;   // FLG_MAINTAIN_OBJECT_TYPELIST
            ULONG HeapEnableTagByDll : 1;       // FLG_HEAP_ENABLE_TAG_BY_DLL
            ULONG DisableStackExtension : 1;    // FLG_DISABLE_STACK_EXTENSION
            ULONG EnableCsrDebug : 1;           // FLG_ENABLE_CSRDEBUG
            ULONG EnableKDebugSymbolLoad : 1;   // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
            ULONG DisablePageKernelStacks : 1;  // FLG_DISABLE_PAGE_KERNEL_STACKS
            ULONG EnableSystemCritBreaks : 1;   // FLG_ENABLE_SYSTEM_CRIT_BREAKS
            ULONG HeapDisableCoalescing : 1;    // FLG_HEAP_DISABLE_COALESCING
            ULONG EnableCloseExceptions : 1;    // FLG_ENABLE_CLOSE_EXCEPTIONS
            ULONG EnableExceptionLogging : 1;   // FLG_ENABLE_EXCEPTION_LOGGING
            ULONG EnableHandleTypeTagging : 1;  // FLG_ENABLE_HANDLE_TYPE_TAGGING
            ULONG HeapPageAllocs : 1;           // FLG_HEAP_PAGE_ALLOCS
            ULONG DebugInitialCommandEx : 1;    // FLG_DEBUG_INITIAL_COMMAND_EX
            ULONG DisableDbgPrint : 1;          // FLG_DISABLE_DBGPRINT
            ULONG CritSecEventCreation : 1;     // FLG_CRITSEC_EVENT_CREATION
            ULONG LdrTopDown : 1;               // FLG_LDR_TOP_DOWN
            ULONG EnableHandleExceptions : 1;   // FLG_ENABLE_HANDLE_EXCEPTIONS
            ULONG DisableProtDlls : 1;          // FLG_DISABLE_PROTDLLS
        } NtGlobalFlags;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    KAFFINITY ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    PRTL_BITMAP TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
    PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
    PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    PVOID SparePointers[2];
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo;
    union
    {
        ULONG AppModelFeatureState;
        struct
        {
            ULONG ForegroundBoostProcesses : 1;
            ULONG AppModelFeatureStateReserved : 31;
        };
    };
    ULONG SpareUlongs[2];
    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;
    PWER_PEB_HEADER_BLOCK WerRegistrationData;
    PVOID WerShipAssertPtr;
    union
    {
        PVOID pContextData;
        PVOID EcCodeBitMap;
    };
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;       // ETW heap tracing enabled.
            ULONG CritSecTracingEnabled : 1;    // ETW lock tracing enabled.
            ULONG LibLoaderTracingEnabled : 1;  // ETW loader tracing enabled.
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    PLEAP_SECOND_DATA LeapSecondData;
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1; // Leap seconds enabled.
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask;
} PEB, *PPEB;

FARPROC WINAPI GetProcAddress(HINSTANCE hModule, LPCSTR lpProcName);
DWORD BaseSetLastNTError( _In_ NTSTATUS Status );
PVOID WINAPI BasepMapModuleHandle(HMODULE hModule, BOOLEAN AsDataFile);

#ifdef __cplusplus
}
#endif

#endif // WINDOWS_H
