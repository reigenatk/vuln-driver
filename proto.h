
// a macro to print out a string in WinDBG
#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[rose][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)

typedef struct _RELOCATION_ENTRY
{
	unsigned Type : 4;
	unsigned Offset : 12;
};

typedef struct MyIrpStruct
{
    // address of krnl module
    void* ntoskrnl;

    // addresses of these functions
    void (*nt_memcpy)(void* dst, void* src, size_t len);
    void* (*nt_ExAllocatePoolWithTag)(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag);
    NTSTATUS(*nt_PsCreateSystemThread)(PHANDLE ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, void* StartRoutine, PVOID StartContext);
    void* nt_IofCompleteRequest;

    // offset to these functions are found using pdb parser in exploit. They are NOT EXPORTED from ntoskrnl which is why we gotta do this
    uintptr_t nt_MiLookupDataTableEntry;
    uintptr_t nt_PsGetNextProcess;
    uintptr_t nt_ExUnlockHandleTableEntry;

    // address of driver object once it gets allocated
    void* my_driver;

    // payload (which will just be the entire manualmapped "MyDriver1.sys")
    SIZE_T payload_size;
    UCHAR payload[];
} MyIrpStruct;
