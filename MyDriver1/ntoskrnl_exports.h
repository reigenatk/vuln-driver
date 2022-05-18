#pragma once

// use undocumented function "ObReferenceObjectByName" to get ptr to driver?
// http://www.codewarrior.cn/ntdoc/wrk/ob/ObReferenceObjectByName.htm
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext OPTIONAL, PVOID* Object);

// full struct at https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef struct _LDR_DATA_TABLE_ENTRY
{
	char pad[0x68];
	ULONG Flags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct HANDLE_TABLE_ENTRY {
	void* ObjectPtr;
	ACCESS_MASK GrantedAccessBits; // DWORD at 0x08
} HANDLE_TABLE_ENTRY;

typedef struct OBJECT_HEADER {
	char pad[0x18];
	UCHAR type_index; // use ObGetObjectType to get real type index https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a
} OBJECT_HEADER;

typedef struct OBJECT_TYPE {
	char pad[0x10];
	UNICODE_STRING Name;
	char pad2[0x8];
	UCHAR index;
} OBJECT_TYPE;

extern NTSYSAPI POBJECT_TYPE IoDriverObjectType;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information
#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)
#define SYNCHRONIZE                      (0x00100000L)
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)

// exported from ntoskrnl, gets name of process given the pointer to the EPROCESS object
NTSYSAPI const char* PsGetProcessImageFileName(PEPROCESS Process);
// exported from ntoskrnl, gets process object given the process id
NTSYSAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);

// all these structs are via winDBG
//typedef struct HANDLE_TABLE {
//	char pad[0x8];
//	uintptr_t table_code;
//} HANDLE_TABLE;

// this function takes a pointer to an object as argument and returns pointer to an OBJECT_TYPE 
// https://github.com/processhacker/processhacker/blob/1aa402b6a29e8b60d5c93c8385c68f719896cb24/KProcessHacker/include/ntfill.h
NTKERNELAPI POBJECT_TYPE NTAPIObGetObjectType(PVOID Object);

typedef void* HANDLE_TABLE;

typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(HANDLE_TABLE* HandleTable, IN HANDLE_TABLE_ENTRY* HandleTableEntry, IN HANDLE Handle, IN PVOID EnumParameter);


NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(PVOID Object);

NTSYSAPI BOOLEAN NTAPI ExEnumHandleTable(HANDLE_TABLE* HandleTable, EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle);
// online i also found this but IDA says there's four arguments. IDK.
// typedef BOOLEAN (*EX_ENUMERATE_HANDLE_ROUTINE)(IN PHANDLE_TABLE_ENTRY HandleTableEntry, IN HANDLE Handle, IN PVOID EnumParameter);

// From PnpHandleProcessWalkWorker. Gets the pointer to the object that the handle is to, given the object pointer field for the handle table entry
#define HandleTableEntryToObjectPtr(ObjectPtr) ((((__int64)(ObjectPtr) >> 16LL) & 0xFFFFFFFFFFFFFFF0ui64) + 0x30)


// http://www.codewarrior.cn/ntdoc/winnt/mm/MiLookupDataTableEntry.htm
// NON EXPORTED, but pdb parser. Define as function ptr
// RESOLVED BY PDB PARSER
PLDR_DATA_TABLE_ENTRY(*MiLookupDataTableEntry)(PVOID AddressWithinSection, ULONG ResourceHeld);

// RESOLVED BY PDB PARSER
PEPROCESS(*PsGetNextProcess)(IN PEPROCESS OldProcess);

// RESOLVED BY PDB PARSER
__int64 (*ExUnlockHandleTableEntry)(HANDLE_TABLE* HandleTable, HANDLE_TABLE_ENTRY* HandleTableEntry);

// OFFSETS
#define HANDLE_TABLE_OFFSET 0x570 // from EPROCESS
#define OBREGISTERCALLBACKS_FLAGS 0x20
#define FREESPACE_IN_NULL_DRIVER 0x2F0
#define FOUR_KB 0x1000
#define TYPE_OBJECT_PROCESS_INDEX 7 
#define SYSTEM_PROCESS_ID 4