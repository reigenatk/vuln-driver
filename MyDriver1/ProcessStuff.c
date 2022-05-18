#include <wdm.h>

#include "ProcessStuff.h"
#include "proto.h"

PLIST_ENTRY listHead;
EX_SPIN_LOCK spinlock;

void initializeProcessLinkedList() {
	InitializeListHead(listHead);
	RtlZeroMemory(&spinlock, sizeof(EX_SPIN_LOCK));
}

MyProcessInfo* insertNewProcessEntry(PEPROCESS creating, PEPROCESS process, ULONG InitialGraceExpired) {
	MyProcessInfo* n = (MyProcessInfo*) ExAllocatePool(NonPagedPool, sizeof(MyProcessInfo));
	if (!n) {
		DBG_LOG("ExAllocatePool fails\n");
		__debugbreak();
	}
	n->CreatingProcess = creating;
	n->Process = process;
	n->InitialGraceExpired = InitialGraceExpired;

	// make sure object doesnt get deleted?
	ObReferenceObject(process);
	ObReferenceObject(creating);
	InsertHeadList(listHead, &n->ListEntry);
	return n;
}

MyProcessInfo* findMatchingProcessInfo(PEPROCESS process) {
	// go through entire thing
	PLIST_ENTRY p = listHead;
	while (p->Flink != listHead) {
		p = p->Flink;
		MyProcessInfo* m = CONTAINING_RECORD(p, MyProcessInfo, ListEntry);
		if (m->Process == process) {
			// matches
			return m;
		}
	}
	return NULL;
}

PEPROCESS LookupCreatingProcess(PEPROCESS process) {
	MyProcessInfo* match = findMatchingProcessInfo(process);
	PEPROCESS creating_process = match->CreatingProcess;
	if (creating_process) {
		return creating_process;
	}
	else {
		return NULL;
	}
}

void removeProcessEntry(MyProcessInfo* m) {
	RemoveEntryList(&m->ListEntry);
	ObDereferenceObject(m->CreatingProcess);
	ObDereferenceObject(m->Process);
	ExFreePool(m);
}

void freeLinkedList() {
	// go thru each entry in linked list and remove it
	PLIST_ENTRY p = listHead;
	while (p->Flink) {
		p = p->Flink;
		MyProcessInfo* m = CONTAINING_RECORD(p, MyProcessInfo, ListEntry);
		removeProcessEntry(m);
	}
}