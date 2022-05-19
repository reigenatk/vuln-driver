//#pragma once
//
//#define INITIAL_NUM_HANDLES_ALLOWED 30
//
//typedef struct {
//    PEPROCESS Process;
//    PEPROCESS CreatingProcess;
//    ULONG InitialGraceExpired;
//    LIST_ENTRY ListEntry;
//} MyProcessInfo;
//
//// insert an entry into linked list
//MyProcessInfo* insertNewProcessEntry(PEPROCESS creating, PEPROCESS process);
//
//// find an entry in linked list with matching process
//MyProcessInfo* findMatchingProcessInfo(PEPROCESS process);
//
//// lookup the creating process given a process pointer. Returns NULL if no creator
//PEPROCESS LookupCreatingProcess(PEPROCESS process);
//
//// linked list remove
//void removeProcessEntry(MyProcessInfo* m);
//
//// call this at the very beginning to initialize linkedlist
//void initializeProcessLinkedList();
//
//// delete the entire contents of linkedlist. Call this when unloading driver
//void freeLinkedList();
//
//// this function is in charge of determining if a process has exhausted its original allotment of handles
//BOOLEAN SubtractOneHandle(PEPROCESS process);
//
//// make this global so Source.c can use the lock too
//extern EX_SPIN_LOCK spinlock;

#pragma once

typedef struct {
    PEPROCESS Process;
    PEPROCESS CreatingProcess;
    ULONG InitialGraceExpired;
    LIST_ENTRY ListEntry;
} MyProcessInfo;

MyProcessInfo* LookupMyProcessInfo(PEPROCESS Process);
PEPROCESS LookupCreatingProcess(PEPROCESS Process);
BOOLEAN MyProcessInfoAllowOnce(PEPROCESS Process);
void FreeMyProcessInfo(MyProcessInfo* myProcessInfo);
MyProcessInfo* CreateMyProcessInfo(PEPROCESS Process, PEPROCESS CreatingProcess);
void InitializeMyProcessInfoList();
void FreeMyProcessInfoList();

extern EX_SPIN_LOCK MyProcessInfoListLock;