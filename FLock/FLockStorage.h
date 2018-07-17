//
// Project:
//
//		Data Guard FLock driver.
//
// Author:
//
//		Burlutsky Stanislav
//		burluckij@gmail.com
//

#pragma once

#include "flock.h"
#include "FLock_shared.h"


/* Max size for the storage. */
#define FLOCK_MAX_STORAGE_SIZE		(1024 * 1024 * 10)
#define STORAGE_BASE_ARRAY_SIZE		50
#define FLOCK_STORAGE_SIGNATURE		0x12FA7788



//////////////////////////////////////////////////////////////////////////
//
// Structures are defined here.
//

#pragma pack(push, 1)

typedef struct _FLOCK_STORAGE_HEADER
{
	DWORD signature; // = FLOCK_STORAGE_SIGNATURE;
	ULONG length;

} FLOCK_STORAGE_HEADER, *PFLOCK_STORAGE_HEADER;

typedef struct _FLOCK_STORAGE_ENTRY
{
	UCHAR version;
	UCHAR id[16];
	ULONG32 flockFlag;
}FLOCK_STORAGE_ENTRY, *PFLOCK_STORAGE_ENTRY;

typedef struct _FLOCK_STORAGE
{
	//
	// Lock map area.
	//
	//////////////////////////////////////////////////////////////////////////
	HANDLE		hFile;
	HANDLE		hSection;
	PVOID		pMappedData;
	SIZE_T /*ULONG*/		mapSize;
	ERESOURCE	lockMap;
	// LARGE_INTEGER mapFileSize;
	//////////////////////////////////////////////////////////////////////////

	//
	// Lock array area.
	//
	//////////////////////////////////////////////////////////////////////////
	//ULONG		countEntries;
	BOOLEAN		hasUserObjectsToHide; // TRUE if storage has one or more objects to hide.
	BOOLEAN		hasUserObjectsToLock; // TRUE if storage has one or more objects with locked access policy.
	ULONG		arrayLength;
	ULONG		arrayMaxLength; // Max size of flockArray. 
	ERESOURCE	lockArray;
	PFLOCK_STORAGE_ENTRY flockArray; // NonPaged buffer.
	//////////////////////////////////////////////////////////////////////////

	LONG initializationState; // Zero if the storage is not initialized.

}FLOCK_STORAGE, *PFLOCK_STORAGE;


#pragma pack(pop)


//
// Initializes synchronization primitives for future work.
// Please, do not call that function twice and more times.
//
EXTERN_C BOOLEAN FLockStorageInit();

//
// Returns TRUE if internal storage structures initialized.
//
EXTERN_C BOOLEAN FLockStorageIsInitialized();


//
// Does completely opposite actions to FLockStorageInit(..):
// - Delete all earlier initialized synchronization objects.
// - If you have ever called FLockStorageInit(..) that you should called this routine and only once.
//
EXTERN_C BOOLEAN FLockStorageDeinitialize();


//
// Creates or opens the storage file exclusively.
//
EXTERN_C BOOLEAN FLockStorageOpen();

//
// Returns TRUE if the storage file was exclusively opened.
//
EXTERN_C BOOLEAN FLockStorageIsOpened();

//
// Creates mapping of the storage file into memory.
//
EXTERN_C BOOLEAN FLockStorageLoad();

//
// Returns TRUE if storage data was mapped into memory.
//
EXTERN_C BOOLEAN FLockStorageIsLoaded();

//
// Close handle of previously opened file of the storage, using ZwClose(..) call.
//
EXTERN_C BOOLEAN FLockStorageClose();

//
// Increases file file mapping view to target size.
//
EXTERN_C BOOLEAN FLockStorageIncreaseMap(
	ULONG _targetSize
	);

//
// Imports all storage information about FLocks into NonPaged memory.
// I.e. It makes a second copy of already mapped data.
//
EXTERN_C BOOLEAN FLockStorageImport();

//
// Writes all FLocks entries from an array in non-paged memory to mapped file on disk.
//
EXTERN_C BOOLEAN FLockStorageExportOnDisk();


EXTERN_C BOOLEAN FLockStorageUnload();
//EXTERN_C BOOLEAN FLockStorageFlush();


EXTERN_C BOOLEAN FLockStorageFlushMapped();


EXTERN_C BOOLEAN FLockStorageAdd(
	PUCHAR _flockId, // Pointer to UCHAR[16] array.
	ULONG actionPolicy
	);


EXTERN_C BOOLEAN FLockStorageAddWithFlush(
	PUCHAR _flockId, // Pointer to UCHAR[16] array.
	ULONG flockFlag
	);


EXTERN_C BOOLEAN FLockStorageRemove(
	PUCHAR _flockId // Pointer to UCHAR[16] array.
	);


EXTERN_C BOOLEAN FLockStorageRemoveWithFlush(
	PUCHAR _flockId // Pointer to UCHAR[16] array.
	);


//
// Clears all entries in memory and on disk.
//
EXTERN_C BOOLEAN FLockStorageClear();

//
// Makes copy of all available FLocks.
//
// _useNonPagedMemory - does it need to allocate NonPaged memory? TRUE if it is.
// _copiedNumbers - count copied entries.
// _poutBuffer - array with entries, do not forget to free memory allocated for using ExFreePool(..).
//
EXTERN_C BOOLEAN FLockStorageGetAll(
	__in BOOLEAN _useNonPagedMemory,
	__out PULONG _copiedNumbers,
	__out PFLOCK_STORAGE_ENTRY* _poutBuffer
	);


EXTERN_C BOOLEAN FLockStorageLookup(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__out PFLOCK_STORAGE_ENTRY _foundResult
	);

EXTERN_C BOOLEAN FLockStorageIsPresent(
	__in PUCHAR _flockId // Pointer to UCHAR[16] array.
	);


EXTERN_C BOOLEAN FLockStorageVerifyLock(
	__in PUCHAR _flockId // Pointer to UCHAR[16] array.
	);

EXTERN_C BOOLEAN FLockStorageVerifyFlag(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__in DWORD	_flag
	);

EXTERN_C BOOLEAN FLockStorageUpdateEntry(
	__in PFLOCK_STORAGE_ENTRY _changedEntry
	);

//
// Returns TRUE if the storage has one or more hidden user files.
//
EXTERN_C BOOLEAN FLockStorageHasHiddenUserObjects();

//
// Returns TRUE if the storage has one or more user files to with locked access.
//
EXTERN_C BOOLEAN FLockStorageHasLockedUserObjects();
