#include <Ntddk.h>
#include <intrin.h>
#include <ntimage.h>

#include <stdint.h>
#include <wdm.h>
#include "proto.h"
#include "ntoskrnl_exports.h"
#include "ProcessStuff.h"


char* target_process = "csgo.exe";


NTSTATUS ret;
PKTIMER timer;

// this is our bytecode that we overwrite the beep ioctl handler with.
// We use it to write into beep driver's memory, the program image of a driver executable, specifically, the driverentry function below
// The program image is mapped at virt address 'some_memory' in the kernel. Then we start a kernel thread on it, letting running whatever driver code we would like in the kernel
// 
__int64 __declspec(dllexport) __fastcall MyIRPControl(struct _DEVICE_OBJECT* a1, IRP* a2) {
    // _IO_STACK_LOCATION* curStackIrp = a2->Tail.Overlay.CurrentStackLocation;
    // uint32_t controlCode = curStackIrp->Parameters.Read.ByteOffset.LowPart;

  // this is the raw input, we know this cuz we reverse the driver and know that other stuff is stripped
    MyIrpStruct* buf = (MyIrpStruct*)a2->AssociatedIrp.SystemBuffer;

    // allocate memory
    void* some_memory = buf->nt_ExAllocatePoolWithTag(NonPagedPoolExecute, buf->payload_size, (ULONG)"hi");
    // pass this address back to the struct
    buf->my_driver = some_memory;

    // copy entire driver 
    // buf->nt_memcpy(some_memory, buf->payload, buf->payload_size);

  // test this lol 
    buf->nt_memcpy(some_memory, buf->payload, buf->payload_size);

    // headers
    PIMAGE_DOS_HEADER image = (PIMAGE_DOS_HEADER)some_memory;
    PIMAGE_NT_HEADERS fileHeader = (PIMAGE_NT_HEADERS)((uintptr_t)some_memory + image->e_lfanew);

    // relocs
    // IMG DATA DIRECTORY from Optional Header (addr and size of table)
    IMAGE_DATA_DIRECTORY* reloc_directory_info = (IMAGE_DATA_DIRECTORY*)&fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)some_memory + reloc_directory_info->VirtualAddress);
    void* reloc_table_end = (void*)((uintptr_t)cur_reloc + reloc_directory_info->Size);

    uintptr_t imageBaseDifference = (uintptr_t)some_memory - fileHeader->OptionalHeader.ImageBase;

    // loop through all relocs in reloc DIRECTORY
    while (cur_reloc != reloc_table_end) {
        ULONG size_of_block = cur_reloc->SizeOfBlock;
        ULONG rva = cur_reloc->VirtualAddress;

        // loop through all entries in this current reloc (2 bytes each)
        int num_entries = (size_of_block - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(__int16);
        // printf("Relocing %d entries\n", num_entries);

        // skip the first 8 bytes (its just descriptor info)
        uint16_t* reloc_entry = (uint16_t*)((uintptr_t)cur_reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (int i = 0; i < num_entries; i++) {
            // high 4 bits is the offset type, low 12 is the offset
            uint16_t offset = *reloc_entry & 0xFFF;
            USHORT reloc_type = *reloc_entry >> 12;


            // reloc type #0 (absolute) and #10 (DIR64) is most common.
            if (reloc_type == IMAGE_REL_BASED_DIR64) {
                // printf("reloc of type IMAGE_REL_BASED_DIR64 at offset %#x+%#llx\n", rva, offset);

                // access the memory at the relocation spot, and set it equal to the imagebase difference
                ULONG64* reloc_spot = (ULONG64*)((uintptr_t)some_memory + rva + offset);
                *reloc_spot += imageBaseDifference;
            }
            else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
                // printf("reloc of type IMAGE_REL_BASED_ABSOLUTE at offset %#x+%#llx\n", rva, offset);
            }
            else {
                // printf("Reloc type not supported: type %x\n", reloc_type);
                // bye();
            }
            reloc_entry++;
        }
        // add the size of the reloc section to get to next reloc descriptor
        cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)cur_reloc + cur_reloc->SizeOfBlock);
    }

    // call the code that resides at this memory, which is our shellcode. Cast it to a void function with no args.
    // ((void(*)())some_memory)();

  // allocate some new space for the start context (not sure if this is necessary)
  // PVOID start_context = buf->nt_ExAllocatePoolWithTag(NonPagedPoolExecute, sizeof(MyIrpStruct), "hi2");
  // __movsb(start_context, buf, sizeof(MyIrpStruct));

    HANDLE hThread;

    // this assumes .text section for our driver starts at 4KB, which is default. Doing start_addr = some_memory + pe->OptionalHeader.AddressOfEntryPoint 
    // doesn't work unless you go into VS settings and set the DriverEntry routine to be entry point in Linker->Advanced
    void* start_addr = (void*)((uintptr_t)some_memory + FOUR_KB);
    buf->nt_PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)start_addr, buf);

    // cast teh void* in the struct to this function def instead then call it
    ((void (*)(PIRP, CCHAR))buf->nt_IofCompleteRequest)(a2, 0);
    return 0;
}

BOOLEAN isAllowedProgram(char* requesting_process) {
    // 
    if (strstr(requesting_process, "csrss") || strstr(requesting_process, "lsass") || strstr(requesting_process, "x32dbg") || strstr(requesting_process, "dllinjector")
         || strstr(requesting_process, "svchost") || strstr(requesting_process, "explorer.exe") || strstr(requesting_process, "WerFault.exe") || strstr(requesting_process, "system")
        || strstr(requesting_process, "MsMpEng") || strstr(requesting_process, target_process), strstr(requesting_process, "steam.exe") ||
        strstr(requesting_process, "ProcessHacker") || strstr(requesting_process, "cheatengine") || strstr(requesting_process, "CSGODLL")) {
        return TRUE;
    }
    return FALSE;
}

// we will use these variables to keep track of our driver's execution state 
volatile LONG isUnloading;
volatile LONG ScanHandlesQueue;
volatile LONG stuffToReleaseBeforeUnload;

// this is "xor eax eax, ret" (return 0)
// char shellcode[] = { 0x31, 0xc0, 0xc3 };

// do the trampoline
UCHAR Trampoline[] = {
  0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
  0xff, 0xe0 // jmp rax
};

uintptr_t patchaddr_1;
uintptr_t patchaddr_2;

PVOID null_text_section_start;

PDRIVER_OBJECT pNullDriverObj;
PVOID callback_handle;
PVOID notif_routine_trampoline;
PVOID nullDrvSectionHandle;

void MyUnloadRoutine(PVOID StartContext) {
    DBG_LOG("Unload thread executing!\n");

    // put in a short delay (10ms)
    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * 10;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    // unregister callback
    ObUnRegisterCallbacks(callback_handle);
    DBG_LOG("ObUnRegisterCallbacks done!\n");

    PsSetCreateProcessNotifyRoutineEx(notif_routine_trampoline, TRUE);
    DBG_LOG("Unregistered process notification routine!\n");

    while (stuffToReleaseBeforeUnload != 0) {
        YieldProcessor();
    }

    //// free process linked list
    // FreeMyProcessInfoList();
    // DBG_LOG("Freed Process linked list\n");

    //// free the timer, stop any queueing DPCs that havent run yet
    //// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kecanceltimer
    KeCancelTimer(&timer);
    DBG_LOG("Cancelled DPC timers.\n");
    //// is this even necessary? I guess its good practice?
    ObDereferenceObject(pNullDriverObj);

    //// release page from the main memory so it can be paged out again
    MmUnlockPagableImageSection(nullDrvSectionHandle);
    DBG_LOG("Unlocked Null device text page.\n");
}

KDEFERRED_ROUTINE KdeferredRoutine;
KDPC Dpc;

// adds a task to the scan handles queue immediately
void KdeferredRoutine(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    DBG_LOG("DPC executing!\n");

    // this DPC runs at DISPATCH_LEVEL which is too high to do anything. So we just increment scanhandles queue which runs at APC_LEVEL Instead.
    InterlockedIncrement(&ScanHandlesQueue);

    InterlockedDecrement(&stuffToReleaseBeforeUnload);
}


void UnloadDriver() {

    DBG_LOG("Running Unload Driver\n");
    HANDLE threadHandle;
    PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)MyUnloadRoutine, NULL);
}


// our pre-operation callback to restore max handle access. This gets called whenever a handle is either created or duplicated, for process, thread and desktop handles
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration
// for OPERATION_INFORMATION https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information
OB_PREOP_CALLBACK_STATUS my_preoperation_callback(
    PVOID                         RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    InterlockedIncrement(&stuffToReleaseBeforeUnload);

    // distinguish between which operation is being done (create or duplicate?), and hence also figuring out which access we need to change
    ACCESS_MASK* pDesiredAccess;
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        pDesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else {
        DBG_LOG("Operation not defined\n");
        goto done;
    }
    // no kernel handles should be messed with
    if (OperationInformation->KernelHandle) {
        goto done;
    }
    // if it is on a handle to a process
    if (OperationInformation->ObjectType == *PsProcessType) {
        // this just gets process name of currently running process (the one trying to get a handle)
        char* requesting_process = PsGetProcessImageFileName(IoGetCurrentProcess());
        PEPROCESS handle_process = OperationInformation->Object;
        char* handle_process_name = PsGetProcessImageFileName(handle_process);

        if (strstr(handle_process_name, "doskey.exe")) {
            // prevents there from being multiple calls to UnloadDriver, in other words, ensures it only gets called once 
            // by changing a global variable atomically to 1 to indicate it has been done already
            LONG init_val = InterlockedCompareExchange(&isUnloading, 1, 0);
            if (init_val == 0) {
                UnloadDriver();
                goto done;
            }
        }

        // enable this if you wanna see ALL accesses, careful tho because it will spam the console pretty badly
        // DBG_LOG("%s tried to get perms to a handle at %s\n", requesting_process, handle_process_name);

        // if the handle its trying to get is to our target process we're tryna protect
        if (strstr(handle_process_name, target_process)) {

            if (isAllowedProgram(requesting_process) || !strcmp("csrss.exe", requesting_process) || PsGetProcessId(IoGetCurrentProcess()) == 4 || !strcmp("System", requesting_process)) {
                DBG_LOG("I know you, %s. You can get a handle to %s.\n", requesting_process, target_process);
                goto done;
            }
            // look up who created this process
            // PEPROCESS p = LookupCreatingProcess(handle_process);

            // if the process requesting a handle is the same as the one who created it, queue a DEFERRED routine to examine the handle after process has been made
            //if (0) { // p && p == IoGetCurrentProcess()
            //  DBG_LOG("creator process asking for handle\n");
            //  BOOLEAN allowed_to_have_more_handles = SubtractOneHandle(IoGetCurrentProcess());
            //  if (allowed_to_have_more_handles == TRUE) {
            //    // let it have handle, but first query a DPC to revoke his right to the handles after a set amount of time

            //    LARGE_INTEGER interval;
            //    interval.QuadPart = -10000 * 5000; // 5 seconds
            //    BOOLEAN WasAlreadyQueued = KeSetTimerEx(&timer, interval, 100, &Dpc);
            //    if (!WasAlreadyQueued) {
            //      // then DPC will run so mark that
            //      InterlockedIncrement(&stuffToReleaseBeforeUnload);
            //    }
            //    goto done;
            //  }
            //}
            /*else {*/
              // https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
            uint64_t minimal_rights = SYNCHRONIZE | PROCESS_TERMINATE;
            *pDesiredAccess = minimal_rights;
            DBG_LOG("get away from my %s, %s! Given minimal rights of %x\n", target_process, requesting_process, minimal_rights);
            goto done;
            /*}*/

        }
    }
    // if it is a handle to a thread
    if (OperationInformation->ObjectType == *PsThreadType) {

        PETHREAD handle_thread = OperationInformation->Object;
        // find what process this thread is in
        HANDLE pid = PsGetThreadProcessId(handle_thread);
        PEPROCESS requesting_process;
        NTSTATUS ret = PsLookupProcessByProcessId(pid, &requesting_process);

        char* requesting_process_name = PsGetProcessImageFileName(requesting_process);
        if (strstr(requesting_process_name, target_process)) {
            DBG_LOG("Process %p tried to access our baby %s using thread at %p, flags requested were %x\n", requesting_process, target_process, handle_thread, OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
            // https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
            *pDesiredAccess = SYNCHRONIZE | THREAD_TERMINATE | THREAD_SUSPEND_RESUME;
        }
        ObDereferenceObject(requesting_process);
    }

done:
    InterlockedDecrement(&stuffToReleaseBeforeUnload);
    return OB_PREOP_SUCCESS;
}

// pass in pointer to EPROCESS as the EnumParameter
BOOLEAN stripHandle(HANDLE_TABLE* HandleTable, HANDLE_TABLE_ENTRY* HandleTableEntry, HANDLE Handle, PVOID EnumParameter) {
    // DBG_LOG("Strip handle called for handle table entry %p, handle %p for handle table %p for process %p\n", HandleTableEntry, Handle, HandleTable, EnumParameter);

    void* object_ptr = HandleTableEntryToObjectPtr(HandleTableEntry->ObjectPtr);
    // DBG_LOG("object ptr %p\n", object_ptr);
    if (!MmIsAddressValid(object_ptr)) {
        // DBG_LOG("invalid object ptr %p\n", object_ptr);
        goto exit;
    }
    OBJECT_TYPE* obj_type = ObGetObjectType(object_ptr);
    if (!MmIsAddressValid(obj_type)) {
        // DBG_LOG("invalid obj_type %p\n", obj_type);
        goto exit;
    }
    PWCH ObjectTypeIndex = obj_type->Name.Buffer;

    if (wcscmp(ObjectTypeIndex, L"Process")) {
        // DBG_LOG("Not a process handle, type is %S\n", ObjectTypeIndex);
        goto exit;
    }
    // now we know object is a EPROCESS so cast it
    PEPROCESS e = (PEPROCESS)object_ptr;
    char* process_name_1 = PsGetProcessImageFileName(e);
    if (strcmp(process_name_1, target_process) != 0) {
        // DBG_LOG("Process handle isn't to %s, its to %s\n", target_process, process_name_1);
        goto exit;
    }

    PEPROCESS handle_owning_process = (PEPROCESS)EnumParameter;
    char* owning_process_name = PsGetProcessImageFileName(handle_owning_process);
    // dont downgrade handles from cheatengine, x32dbg, our dll injector (who will need a handle to csgo to inject) and ProcessHacker
    if (isAllowedProgram(owning_process_name)) {
        // then it is allowed
        DBG_LOG("Handle is from allowed program %s\n", owning_process_name);
        goto exit;
    }

    ACCESS_MASK current_access = HandleTableEntry->GrantedAccessBits;
    DBG_LOG("Handle to %s from %s needs to be inspected. Original access %#x\n", target_process, owning_process_name, current_access);

    // demote privs
    if ((current_access & PROCESS_DUP_HANDLE)) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_DUP_HANDLE;
        DBG_LOG("stripping PROCESS_DUP_HANDLE\n");
    }
    if (current_access & PROCESS_CREATE_THREAD) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_CREATE_THREAD;
        DBG_LOG("stripping PROCESS_CREATE_THREAD\n");
    }
    if (current_access & PROCESS_QUERY_INFORMATION) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_QUERY_INFORMATION;
        DBG_LOG("stripping PROCESS_QUERY_INFORMATION\n");
    }
    if (current_access & PROCESS_QUERY_LIMITED_INFORMATION) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_QUERY_LIMITED_INFORMATION;
        DBG_LOG("stripping PROCESS_QUERY_LIMITED_INFORMATION\n");
    }
    if (current_access & PROCESS_SET_INFORMATION) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_SET_INFORMATION;
        DBG_LOG("stripping PROCESS_SET_INFORMATION\n");
    }
    if (current_access & PROCESS_SET_LIMITED_INFORMATION) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_SET_LIMITED_INFORMATION;
        DBG_LOG("stripping PROCESS_SET_LIMITED_INFORMATION\n");
    }
    if (current_access & PROCESS_VM_READ) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_VM_READ;
        DBG_LOG("stripping PROCESS_VM_READ\n");
    }
    if (current_access & PROCESS_VM_WRITE) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_VM_WRITE;
        DBG_LOG("stripping PROCESS_VM_WRITE\n");
    }
    if (current_access & PROCESS_VM_OPERATION) {
        HandleTableEntry->GrantedAccessBits &= ~PROCESS_VM_OPERATION;
        DBG_LOG("stripping PROCESS_VM_OPERATION\n");
    }
    DBG_LOG("Handle now has flags %#x\n", HandleTableEntry->GrantedAccessBits);

exit:
    // unlock handle table entry so ExEnumHandleTable can move to next one
    ExUnlockHandleTableEntry(HandleTable, HandleTableEntry);

    // needs to be false?
    return FALSE;
}

void WalkHandleTable(PEPROCESS p) {
    // DBG_LOG("Walking handle table for process %p\n", p);
    HANDLE_TABLE* handle_table = *(void**)((uintptr_t)p + HANDLE_TABLE_OFFSET);
    if (handle_table && MmIsAddressValid(handle_table)) {
        // DBG_LOG("Enumerating Handle table at %p for process %s\n", handle_table, PsGetProcessImageFileName(p));
        HANDLE h; // The handle that ExEnumHandleTable stopped at, only valid if the return value is true. We don't really care because we won't use it 

        // this calls striphandle routine for EACH HANDLE IN THE TABLE!
        ExEnumHandleTable(handle_table, stripHandle, p, &h);
    }
    else {
        // DBG_LOG("Invalid handle table at %p\n");
    }
    // DBG_LOG("Done looping handle table\n");

}

void LoopAllProcesses() {
    // example for PsGetNextProcess here https://cpp.hotexamples.com/examples/-/-/PsGetNextProcess/cpp-psgetnextprocess-function-examples.html
    for (PEPROCESS kp = PsGetNextProcess(NULL); kp; kp = PsGetNextProcess(kp))
    {
        //DBG_LOG("kp = %p", kp);
        //DBG_LOG("Hello %s", PsGetProcessImageFileName(kp));
        WalkHandleTable(kp);
        //DBG_LOG("DemoteBadHandles returns.");
    }
    DBG_LOG("Finished one loop of scanning all handles...\n");

}

NTSTATUS StripHandleThread(void* my_start_info)
{
    while (!isUnloading)
    {
        // Wait until we have something to do
        while (!ScanHandlesQueue && !isUnloading) {
            YieldProcessor();
        }
        if (isUnloading) {
            break;
        }

        LoopAllProcesses();

        InterlockedDecrement(&ScanHandlesQueue);
    }

    DBG_LOG("StripHandle thread terminating\n");

    InterlockedDecrement(&stuffToReleaseBeforeUnload); // was incremented when we started the thread

    return STATUS_SUCCESS;
}

NTSTATUS WorkQueuer(PVOID startContext) {
    while (!isUnloading) {
        // put in a short delay (5000ms)
        LARGE_INTEGER interval;
        interval.QuadPart = -10000 * 5000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (isUnloading) {
            break;
        }
        InterlockedIncrement(&ScanHandlesQueue);
    }

    InterlockedDecrement(&stuffToReleaseBeforeUnload);
    DBG_LOG("WorkQueuer thread terminating!\n");
    return STATUS_SUCCESS;
}

void my_notif_routine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    InterlockedIncrement(&stuffToReleaseBeforeUnload);
    char* name_of_new_process = PsGetProcessImageFileName(Process);
    DBG_LOG("New process called %s is being altered...\n", name_of_new_process, Process, ProcessId);

    // process is being created
    if (CreateInfo) {
        // DBG_LOG("Process is being created...\n");
        // look at info regarding who made this process
        HANDLE creating_pid = CreateInfo->CreatingThreadId.UniqueProcess;
        PWCH cmdline = CreateInfo->CommandLine->Buffer;
        int cmdlinelen = CreateInfo->CommandLine->Length;
        PEPROCESS creating_process;
        NTSTATUS ret = PsLookupProcessByProcessId(creating_pid, &creating_process);
        if (ret != STATUS_SUCCESS) {
            DBG_LOG("PsLookupProcessByProcessId fails\n");
            return;
        }
        else {
            KIRQL irql = ExAcquireSpinLockExclusive(&MyProcessInfoListLock);
            //// add new process into linked list
            // MyProcessInfo* newProcessStruct = CreateMyProcessInfo(Process, creating_process);
            char* creating_process_name = PsGetProcessImageFileName(creating_process);
            DBG_LOG("Process %s was created by %s, pid %d, ran with cmd %S\n", name_of_new_process, creating_process_name, (int)creating_pid, cmdline);
            ObDereferenceObject(creating_process);
            ExReleaseSpinLockExclusive(&MyProcessInfoListLock, irql);
        }


    }
    else {
        DBG_LOG("Process %s is exiting, pid %d, pointer %p\n", name_of_new_process, ProcessId, Process);
        //KIRQL irql = ExAcquireSpinLockExclusive(&spinlock);
        //// find entry with matching Process and creating process and remove it 
        //MyProcessInfo* f = findMatchingProcessInfo(Process);
        //if (!f) {
        //  DBG_LOG("Could not find matching process!\n");
        //}
        //else {
        //  // remove process from linked list
        //  removeProcessEntry(f);
        //}
        //ExReleaseSpinLockExclusive(&spinlock, irql);
    }

    InterlockedDecrement(&stuffToReleaseBeforeUnload);
}

NTSTATUS insertTrampolines() {

    // first find a driver to patch
    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Null");
    // get a pointer to the beep driver OBJECT
    DBG_LOG("IoDriverObjectType %p\n", IoDriverObjectType);
    NTSTATUS ret = ObReferenceObjectByName(
        &driverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&pNullDriverObj);
    DBG_LOG("Null driver at %p, ObReferenceObjectByName return code %x, flags %x\n", pNullDriverObj->DriverStart, ret, pNullDriverObj->Flags);

    if (!pNullDriverObj) {
        DBG_LOG("No driver object!\n");
        return STATUS_UNSUCCESSFUL;
    }

    // The virtual address we want to patch over is the start of the text section of the beep driver which starts at offset 0x1000 virtual (thanks PFF explorer)
    null_text_section_start = (void*)((uintptr_t)pNullDriverObj->DriverStart + FOUR_KB);

    // lock page into memory (cant be swapped out to disk)
    nullDrvSectionHandle = MmLockPagableCodeSection(null_text_section_start);

    // http://www.codewarrior.cn/ntdoc/winnt/mm/MiLookupDataTableEntry.htm
    PLDR_DATA_TABLE_ENTRY Entry = MiLookupDataTableEntry(null_text_section_start, 0);
    if (!Entry)
    {
        DBG_LOG("Wtf? MiLookupDataTableEntry fails");
        return STATUS_UNSUCCESSFUL;
    }
    Entry->Flags |= OBREGISTERCALLBACKS_FLAGS;

    //PLDR_DATA_TABLE_ENTRY DriverSection = (PLDR_DATA_TABLE_ENTRY)pNullDriverObj->DriverSection;
    //DriverSection->Flags |= 0x20;


    // get the physical address corresponding to the virtual address
    PHYSICAL_ADDRESS phys_addr = MmGetPhysicalAddress(null_text_section_start);

    // map it to virtual memory
    PVOID virt_addr = MmMapIoSpace(phys_addr, FOUR_KB, MmNonCached);

    uintptr_t offset1 = 0;
    uintptr_t offset2 = FREESPACE_IN_NULL_DRIVER; // puts it right after the first trampoline

    DBG_LOG("mapped 4KB of null driver's .text section at physical addr %p to virtual addr %p\n", phys_addr, virt_addr);

    if (!virt_addr) {
        return STATUS_SUCCESS;
    }
    // virtual address for where the memory was patched
    unsigned char* byte_ptr1;
    unsigned char* byte_ptr2;

    byte_ptr1 = (unsigned char*)((uintptr_t)virt_addr + offset1);
    byte_ptr2 = (unsigned char*)((uintptr_t)virt_addr + offset2);

    DBG_LOG("Original code 1: %02x %02x %02x\n", byte_ptr1[0], byte_ptr1[1], byte_ptr1[2]);
    DBG_LOG("Original code 2: %02x %02x %02x\n", byte_ptr2[0], byte_ptr2[1], byte_ptr2[2]);

    // put in our desired address into the trampoline bytecode
    *(uint64_t*)(Trampoline + 2) = (DWORD64)my_preoperation_callback;
    DBG_LOG("Address of my_preoperation_callback: %p\n", my_preoperation_callback);

    // copy the entire trampoline into physical mem
    memcpy(byte_ptr1, Trampoline, sizeof(Trampoline));

    *(uint64_t*)(Trampoline + 2) = (DWORD64)my_notif_routine;
    DBG_LOG("Address of my process notification routine: %p\n", my_notif_routine);
    memcpy(byte_ptr2, Trampoline, sizeof(Trampoline));

    DBG_LOG("Patched code at %p: %02x %02x %02x\n", byte_ptr1, byte_ptr1[0], byte_ptr1[1], byte_ptr1[2]);
    DBG_LOG("Patched code at %p: %02x %02x %02x\n", byte_ptr2, byte_ptr2[0], byte_ptr2[1], byte_ptr2[2]);

    MmUnmapIoSpace(virt_addr, FOUR_KB);
    DBG_LOG("Unmapped 4KB of memory at %p\n", virt_addr);

    // this address works since Null is a running driver?
    patchaddr_1 = (uintptr_t)null_text_section_start + offset1;
    patchaddr_2 = (uintptr_t)null_text_section_start + offset2;
    DBG_LOG("patchaddr 1: %#x patchaddr 2: %#x\n", patchaddr_1, patchaddr_2);
}

// execution jumps to here after ioctl handler executes
_Use_decl_annotations_ NTSTATUS DriverEntry(MyIrpStruct* info) {
    DBG_LOG("HELLO FROM DRIVER\n");

    // initialize process linkedlist
    //InitializeListHead(&MyProcessInfoList);
    RtlZeroMemory(&MyProcessInfoListLock, sizeof(MyProcessInfoListLock));

    // driver STATE initialization
    isUnloading = 0;
    ScanHandlesQueue = 0;
    stuffToReleaseBeforeUnload = 0;

    KeInitializeDpc(&Dpc, KdeferredRoutine, NULL);
    KeInitializeTimer(&timer);


    // resolve non-exported functions whose addresses were passed in
    MiLookupDataTableEntry = info->nt_MiLookupDataTableEntry;
    PsGetNextProcess = info->nt_PsGetNextProcess;
    ExUnlockHandleTableEntry = info->nt_ExUnlockHandleTableEntry;

    if (insertTrampolines()) {
        DBG_LOG("Trampoline setup failed\n");
    }

    // do the exploit for ObRegisterCallbacks
    // https://revers.engineering/superseding-driver-altitude-checks-on-windows/
    // We are trying to register our own pre and post operation functions to deny the handle attempts made by VAC. Each time a handle request is made, it will go through our function
    OB_CALLBACK_REGISTRATION my_obj_registration;
    my_obj_registration.Version = OB_FLT_REGISTRATION_VERSION;
    my_obj_registration.OperationRegistrationCount = 1; // one for handles, one for threads

    UNICODE_STRING my_altitude;
    RtlInitUnicodeString(&my_altitude, L"160000"); // altitude doesn't really matter, i put it in the middle of the driver stack somewhere
    my_obj_registration.Altitude = my_altitude;

    PVOID my_reg_context = 0; // doesnt matter, passed to callback routine but we dont use it
    my_obj_registration.RegistrationContext = my_reg_context;

    OB_OPERATION_REGISTRATION my_ob_op_registration[2];

    // just make the pre callback code point to our shellcode
    POB_PRE_OPERATION_CALLBACK my_pre_operation_callback = patchaddr_1;

    // STRICTLY FOR DEBUGGING, not technically necessary
    // use this function to simulate the execution of MmVerifyCallbackFunctionCheckFlags
    PLDR_DATA_TABLE_ENTRY stuff = MiLookupDataTableEntry(null_text_section_start, 0);
    // we expect this to have 0x20 bit set, else it will fail callback registration (thanks IDA)
    DBG_LOG("MiLookupDataTableEntry flags: %x\n", stuff->Flags);

    my_ob_op_registration[0].ObjectType = PsProcessType;
    my_ob_op_registration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    my_ob_op_registration[0].PostOperation = NULL;
    my_ob_op_registration[0].PreOperation = my_pre_operation_callback;

    my_ob_op_registration[1].ObjectType = PsThreadType;
    my_ob_op_registration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    my_ob_op_registration[1].PostOperation = NULL;
    my_ob_op_registration[1].PreOperation = my_pre_operation_callback;

    my_obj_registration.OperationRegistration = my_ob_op_registration;


    // register the callback
    ret = ObRegisterCallbacks(&my_obj_registration, &callback_handle);
    DBG_LOG("ObRegisterCallbacks returns %x\n", ret);

    notif_routine_trampoline = patchaddr_2;
    ret = PsSetCreateProcessNotifyRoutineEx(notif_routine_trampoline, FALSE);
    DBG_LOG("PsSetCreateProcessNotifyRoutineEx returns %d\n", ret);

    HANDLE hThread;
    InterlockedIncrement(&stuffToReleaseBeforeUnload);
    ret = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)WorkQueuer, NULL);
    DBG_LOG("WorkQueuer thread started with code  %d\n", ret);
    ZwClose(hThread); // we dont rly need handle to the thread

    HANDLE hThread2;
    InterlockedIncrement(&stuffToReleaseBeforeUnload);
    ret = PsCreateSystemThread(&hThread2, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)StripHandleThread, NULL);
    DBG_LOG("LoopAllProcesses thread started with code %d\n", ret);
    ZwClose(hThread2); // we dont rly need handle to the thread

    return STATUS_SUCCESS;
}
