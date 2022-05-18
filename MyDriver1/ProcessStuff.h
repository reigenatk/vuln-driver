#pragma once


typedef struct {
    PEPROCESS Process;
    PEPROCESS CreatingProcess;
    ULONG InitialGraceExpired;
    LIST_ENTRY ListEntry;
} MyProcessInfo;

// insert an entry into linked list
MyProcessInfo* insertNewProcessEntry(PEPROCESS creating, PEPROCESS process, ULONG InitialGraceExpired);

// find an entry in linked list with matching process
MyProcessInfo* findMatchingProcessInfo(PEPROCESS process);

// lookup the creating process given a process pointer. Returns NULL if no creator
PEPROCESS LookupCreatingProcess(PEPROCESS process);

// linked list remove
void removeProcessEntry(MyProcessInfo* m);

// call this at the very beginning to initialize linkedlist
void initializeProcessLinkedList();

// delete the entire contents of linkedlist. Call this when unloading driver
void freeLinkedList();