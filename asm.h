#pragma once
#include <cstdint>
#include <windows.h>
#include <cctype>

extern "C" {
    extern uintptr_t pebBase;
    void GetMyPeb();
}

namespace NTDLL {
    extern uintptr_t ldr;
    extern uintptr_t ntBase;
}

// ========== TYPEDEFS =========
typedef LONG NTSTATUS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* f_NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* f_NtReadVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* f_NtWriteVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
    );

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* f_NtQuerySystemInformation)( 
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;     
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;    
    LONG BasePriority;
    HANDLE UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(NTAPI* f_NtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* f_NtFreeVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     FreeType
    );

typedef NTSTATUS(NTAPI* f_NtProtectVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   NumberOfBytesToProtect,
    ULONG     NewAccessProtection,
    PULONG    OldAccessProtection
    );

// ========== SYSCALL DECLARATIONS =========
extern "C" NTSTATUS Syscall_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

extern "C" NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead
);

extern "C" NTSTATUS Syscall_NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
);

extern "C" NTSTATUS Syscall_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

extern "C" NTSTATUS Syscall_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

extern "C" NTSTATUS Syscall_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass, 
    PVOID ProcessInformation,      
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ========== HELPER FUNCTIONS =========
extern "C" {
    extern DWORD g_ssn;
    extern DWORD g_ssn_read;
    extern DWORD g_ssn_write;
    extern uintptr_t g_syscallAddr;
    extern DWORD g_ssn_thread;
    extern DWORD g_ssn_QSI;
    extern DWORD g_ssn_QIP;
    extern uintptr_t g_ntOpen;
	extern DWORD g_ssn_allocate;
    extern DWORD g_ssn_free;
	extern DWORD g_ssn_protect;
}

DWORD MyHasher(const char* word);
uintptr_t GetFunctionAddress(DWORD targetHash);
DWORD GetSSN(uintptr_t address, const BYTE* pattern);

template <typename T>
T Read(HANDLE hProc, uintptr_t address) {
    T buffer;
    Syscall_NtReadVirtualMemory(hProc, (PVOID)address, &buffer, sizeof(T), NULL);
    return buffer;
}

template <typename T>
bool Write(HANDLE hProc, uintptr_t address, T value) {
    NTSTATUS status = Syscall_NtWriteVirtualMemory(hProc, (PVOID)address, &value, sizeof(T), NULL);
    return (status == 0);
}
