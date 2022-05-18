/*
#include <wdm.h>
#include "ProcessStuff.h"

// a macro to print out a string in WinDBG
#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[rose][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)


LIST_ENTRY listHead;
EX_SPIN_LOCK spinlock;

void initializeProcessLinkedList() {
	InitializeListHead(&listHead);
	RtlZeroMemory(&spinlock, sizeof(EX_SPIN_LOCK));
}

MyProcessInfo* insertNewProcessEntry(PEPROCESS creating, PEPROCESS process) {
	MyProcessInfo* n = (MyProcessInfo*) ExAllocatePool(NonPagedPool, sizeof(MyProcessInfo));
	if (!n) {
		DBG_LOG("ExAllocatePool fails\n");
		__debugbreak();
	}
	RtlZeroMemory(n, sizeof(MyProcessInfo));
	n->CreatingProcess = creating;
	n->Process = process;
	n->InitialGraceExpired = INITIAL_NUM_HANDLES_ALLOWED;

	// make sure object doesnt get deleted?
	ObReferenceObject(process);
	ObReferenceObject(creating);
	InsertHeadList(&listHead, &n->ListEntry);
	return n;
}

// locked by LookupCreatingProcess
MyProcessInfo* findMatchingProcessInfo(PEPROCESS process) {
	// go through entire thing
	PLIST_ENTRY p = &listHead;
	while (p->Flink != &listHead) {
		p = p->Flink;
		MyProcessInfo* m = CONTAINING_RECORD(p, MyProcessInfo, ListEntry);
		if (m->Process == process) {
			// matches
			return m;
		}
	}
	return NULL;
}


BOOLEAN SubtractOneHandle(PEPROCESS process) {
	KIRQL original_irql = ExAcquireSpinLockExclusive(&spinlock);
	MyProcessInfo* p = findMatchingProcessInfo(process);
	BOOLEAN ret = FALSE;
	if (p) {
		if (p->InitialGraceExpired == 0) {
			return TRUE;
		}
		else {
			p->InitialGraceExpired--;
		}
	}

	ExReleaseSpinLockExclusive(&spinlock, original_irql); 
	return ret;
}

PEPROCESS LookupCreatingProcess(PEPROCESS process) {
	// dont start looking for a process unless 
	KIRQL original_irql = ExAcquireSpinLockExclusive(&spinlock);
	MyProcessInfo* match = findMatchingProcessInfo(process);
	PEPROCESS creating_process = match->CreatingProcess;
	if (creating_process) {
		return creating_process;
	}
	else {
		return NULL;
	}
	ExReleaseSpinLockExclusive(&spinlock, original_irql);
}

void removeProcessEntry(MyProcessInfo* m) {
	RemoveEntryList(&m->ListEntry);
	ObDereferenceObject(m->CreatingProcess);
	ObDereferenceObject(m->Process);
	ExFreePool(m);
}

void freeLinkedList() {
	KIRQL original_irql = ExAcquireSpinLockExclusive(&spinlock);
	// go thru each entry in linked list and remove it
	while (!IsListEmpty(&listHead)) {
		removeProcessEntry(CONTAINING_RECORD(listHead.Flink, MyProcessInfo, ListEntry));
	}
	ExReleaseSpinLockExclusive(&spinlock, original_irql);
}*/

//#include <wdm.h>
//
//// custom process list shit
//
//#include "ProcessStuff.h"
//
//// a macro to print out a string in WinDBG
//#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[rose][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)
//
//EX_SPIN_LOCK MyProcessInfoListLock;
//LIST_ENTRY MyProcessInfoList;
//
//// You need to hold the lock to call this
//MyProcessInfo* LookupMyProcessInfo(PEPROCESS Process)
//{
//	for (LIST_ENTRY* MyListEntry = MyProcessInfoList.Flink; MyListEntry != &MyProcessInfoList; MyListEntry = MyListEntry->Flink)
//	{
//		MyProcessInfo* myShit = CONTAINING_RECORD(MyListEntry, MyProcessInfo, ListEntry);
//		if (myShit->Process == Process)
//			return myShit;
//	}
//	return NULL;
//}
//
//PEPROCESS LookupCreatingProcess(PEPROCESS Process)
//{
//	KIRQL OriginalIrql = ExAcquireSpinLockExclusive(&MyProcessInfoListLock);
//	MyProcessInfo* myShit = LookupMyProcessInfo(Process);
//	PEPROCESS CreatingProcess = myShit ? myShit->CreatingProcess : NULL;
//	ExReleaseSpinLockExclusive(&MyProcessInfoListLock, OriginalIrql);
//	return CreatingProcess;
//}
//
//BOOLEAN MyProcessInfoAllowOnce(PEPROCESS Process)
//{
//	KIRQL OriginalIrql = ExAcquireSpinLockExclusive(&MyProcessInfoListLock);
//	MyProcessInfo* myShit = LookupMyProcessInfo(Process);
//	BOOLEAN Result = FALSE;
//	if (myShit)
//	{
//		Result = myShit->InitialGraceExpired < 30; // allow first 30 handles
//		myShit->InitialGraceExpired++;
//	}
//	ExReleaseSpinLockExclusive(&MyProcessInfoListLock, OriginalIrql);
//	return Result;
//}
//
//// You need to hold the lock to call this
//void FreeMyProcessInfo(MyProcessInfo* myProcessInfo)
//{
//	RemoveEntryList(&myProcessInfo->ListEntry);
//	ObDereferenceObject(myProcessInfo->Process);
//	ObDereferenceObject(myProcessInfo->CreatingProcess);
//	ExFreePool(myProcessInfo);
//}
//
//// You need to hold the lock to call this
//MyProcessInfo* CreateMyProcessInfo(PEPROCESS Process, PEPROCESS CreatingProcess)
//{
//	MyProcessInfo* myShit = ExAllocatePool(NonPagedPool, sizeof(MyProcessInfo));
//	if (!myShit)
//	{
//		DBG_LOG("wtf ExAllocatePool fails");
//		__debugbreak();
//	}
//	RtlZeroMemory(myShit, sizeof(MyProcessInfo));
//	DBG_LOG("Process=%p, CreatingProcess=%p", Process, CreatingProcess);
//	ObReferenceObject(Process);
//	ObReferenceObject(CreatingProcess);
//	myShit->Process = Process;
//	myShit->CreatingProcess = CreatingProcess;
//	myShit->InitialGraceExpired = FALSE;
//	InsertHeadList(&MyProcessInfoList, &myShit->ListEntry);
//	return myShit;
//}
//
//void InitializeMyProcessInfoList()
//{
//	RtlZeroMemory(&MyProcessInfoListLock, sizeof(MyProcessInfoListLock));
//	InitializeListHead(&MyProcessInfoList);
//}
//
//void FreeMyProcessInfoList()
//{
//	KIRQL OriginalIrql = ExAcquireSpinLockExclusive(&MyProcessInfoListLock);
//	while (!IsListEmpty(&MyProcessInfoList))
//	{
//		FreeMyProcessInfo(CONTAINING_RECORD(MyProcessInfoList.Flink, MyProcessInfo, ListEntry));
//	}
//	ExReleaseSpinLockExclusive(&MyProcessInfoListLock, OriginalIrql);
//}