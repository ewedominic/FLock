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


#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma warning(disable:4995)  

//#define NTSTRSAFE_NO_CCH_FUNCTIONS
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <Ntstrsafe.h>

#include "FLock_shared.h"
#include "FLockStorage.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


#define	FLOCK_DEVICE_LINK				L"\\DosDevices\\FLockFsFilter"
#define FLOCK_DEVICE_NAME				L"\\Device\\FLockFsFilter"
#define FLOCK_DEV_NAME					L"\\\\.\\FlockFsFilter"

#define FLOCK_DEVICE					FILE_DEVICE_UNKNOWN /* 0x00002a7b */
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define PTDBG_TRACE_ERRORS				0x00000004
#define PTDBG_TRACE_FULL				(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_OPERATION_STATUS | PTDBG_TRACE_ERRORS)

//
// FLock - file system object (file, dir, volume) which should be protected (locked, hidden).
//

//
// List of request codes.
// All that requests come from user-mode application.
//
//#define IOCTL_FLOCK_XXX	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// Return info about service process.
//
#define IOCTL_FLOCK_GET_SERVICE				CTL_CODE(FLOCK_DEVICE, 0x0712, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Detaches service from driver.
//
#define IOCTL_FLOCK_UNREGISTER_SERVICE		CTL_CODE(FLOCK_DEVICE, 0x0713, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// This is a service registration request.
// There is could be registered only one service.
// Service could be registered twice or more times only if it was crashed or restarted. 
//
#define IOCTL_FLOCK_REGISTER_SERVICE		CTL_CODE(FLOCK_DEVICE, 0x0714, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Query list of all FLocks with detailed information.
#define IOCTL_FLOCK_QUERY_LIST		CTL_CODE(FLOCK_DEVICE, 0x0715, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Adds new FLock for: lock access, hide.
//
#define IOCTL_ADD_FLOCK				CTL_CODE(FLOCK_DEVICE, 0x0716, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Zeros (makes invalid) flock-meta attributes in file's EAs.
//
#define IOCTL_FLOCK_MAKE_BAD		CTL_CODE(FLOCK_DEVICE, 0x0718, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Reads flock-meta from file's EAs.
//
#define IOCTL_FLOCK_READ_META		CTL_CODE(FLOCK_DEVICE, 0x0717, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Returns info about one flock 
//
#define IOCTL_FLOCK_QUERY_ONE		CTL_CODE(FLOCK_DEVICE, 0x0719, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Removes a flock from common flocks list in deriver storage.
//
#define IOCTL_FLOCK_REMOVE			CTL_CODE(FLOCK_DEVICE, 0x0720, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Verifies presence of a flock in common list of known flocks.
//
#define IOCTL_FLOCK_VERIFY			CTL_CODE(FLOCK_DEVICE, 0x0721, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Let as enable\disable protection for the flock.
//
#define IOCTL_FLOCK_MARK			CTL_CODE(FLOCK_DEVICE, 0x0722, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Removes all flock entries in driver's storage.
//
#define IOCTL_FLOCK_CLEAR_ALL		CTL_CODE(FLOCK_DEVICE, 0x0723, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Returns info abut the storage - Was the storage loaded correctly?
//
#define IOCTL_FLOCK_STORAGE_LOADED	CTL_CODE(FLOCK_DEVICE, 0x0724, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//
// Writes flock-meta into EAs.
//
#define IOCTL_FLOCK_MARK_FILE		CTL_CODE(FLOCK_DEVICE, 0x0725, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)


//
// Status codes.
//
#define FLOCK_STATUS_SUCCESS			0
#define FLOCK_STATUS_ERROR				1
#define FLOCK_STATUS_NOT_FOUND			3
#define FLOCK_STATUS_PRESENT			4
#define FLOCK_STATUS_CANT_CHANGE		5
#define FLOCK_STATUS_HAVE_NO_BODY		6
#define FLOCK_STATUS_SMALL_BUFFER		7
#define FLOCK_STATUS_WRONG_DATA			8
#define FLOCK_STATUS_WRONG_SIZE			9
#define FLOCK_STATUS_NOT_LOADED			10


#define	GET_NONPAGED(size)				ExAllocatePool(NonPagedPool, size)
#define GET_NONPAGED_TAG(size)			ExAllocatePoolWithTag(NonPagedPool, size, 'stan');
#define WCHAR_COUNT(len_bytes)					( len_bytes / sizeof(WCHAR))
#define WCHAR_LEN(wchars_count)					(wchars_count * sizeof(WCHAR))


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

#define SETPTR(ptr, data)\
	if(ptr != NULL)\
		(*ptr) = data;

//
// Signature for secure identificating a request to the driver.
//

#define FLOCK_REQUEST_SIGNATURE			{0xA3, 0xFE, 0x01, 0x14, /*1*/ 0xE2, 0xCE, 0x77, 0x21, /*2*/ 0xF3, 0x12, 0x12, 0x01 /*3*/, 0x28, 0x03, 0x19, 0x00 /*4*/}
#define FLOCK_RESPONSE_SIGNATURE		{0x11, 0xC3, 0x21, 0x94, /*1*/ 0xA2, 0xFE, 0x60, 0x08, /*2*/ 0xAA, 0xBE, 0xD3, 0x38 /*3*/, 0x48, 0x51, 0x23, 0x00 /*4*/}

//
// Signature for meta information.
//

#define FLOCK_META_SIGNATURE		{0xB1, 0x0E, 0x21, 0xf4, /*1*/ 0xb2, 0x1E, 0x27, 0x21, /*2*/ 0x12, 0x12, 0x12, 0x12 /*3*/, 0x28, 0x03, 0x92, 0x00 /*4*/}
#define FLOCK_META_NAME				"FLOCK_META" /* 10 bytes */
#define FLOCK_META_NAME_SIZE		10
#define FLOCK_UNIQUE_ID_LENGTH		16

#define FLOCK_FAKE_META_NAME		"AWC10XY34F" /* 10 bytes, should have the same size as FLOCK_META_NAME string. */ 
#define FLOCK_FAKE_META_NAME_SIZE	10

//
// Flag says that the directory includes objects which should be protected.
//
#define FLOCK_FLAG_HAS_FLOCKS		0x01

//
// Flag says that we need ho have an access to the file.
//
#define FLOCK_FLAG_HIDE				0x02

//
// Flag says that we need to protect an access to the file.
//
#define FLOCK_FLAG_LOCK_ACCESS		0x04


#define OFFSET_OF(TYPE, MEMBER) ((ULONG) &((TYPE *)0)->MEMBER)

#pragma pack(push, 1)

//
// All structures should be declared here.
//

typedef enum _FLOCK_OBJECT_TYPE
{
	FLOCK_UNKNOWN = 0,
	FLOCK_FILE = 1,
	FLOCK_DIRECTORY = 2,
	FLOCK_VOLUME = 3
} FLOCK_OBJECT_TYPE;



// 
// This is a meta information which should be in Extended Attributes (EA).
//

typedef struct _FLOCK_META
{
	UCHAR signature[16];
	DWORD version; /* zero by default */
	UCHAR uniqueId[FLOCK_UNIQUE_ID_LENGTH]; /* unique identificator for a file system object */
	DWORD flags;
} FLOCK_META, *PFLOCK_META;

//
// An entry which describes protected file system object.
//

typedef struct _FLOCK_INFO
{
	UCHAR md5UniqueId[FLOCK_UNIQUE_ID_LENGTH]; /* unique identificator for a file system object */
	BOOLEAN lockedState;
	FLOCK_OBJECT_TYPE objectType;
	//wchar_t fsPath[512 + 1]; /* c:\vmod\files\folderhide */
	wchar_t fileName[256 + 1]; /* Sara.doc */

}FLOCK_INFO, *PFLOCK_INFO;


typedef struct _FLOCK_PROTECTION_STATE
{
	LONG canSetEAs;
	LONG canQueryEAs;

	//LONG internal

	LONG countLockedObjects; /* equal to zero if no actively locked objects. */
	ULONG countFlocks; /* Common count of all protected resources. */
	PFLOCK_INFO pFLockList;
	HANDLE hStorage; /* Handle of the main file storage where is info about all flocks. */
}FLOCK_PROTECTION_STATE, *PFLOCK_PROTECTION_STATE;


typedef struct _FLOCK_DEVICE_DATA
{
	PDRIVER_OBJECT driverObject;
	PDEVICE_OBJECT deviceObject;

	UNICODE_STRING	deviceNameUnicodeString;
	UNICODE_STRING	deviceLinkUnicodeString;

	PFLT_FILTER	filterHandle;
	FLOCK_PROTECTION_STATE flockState;

	DWORD serviceProcessId;
	PEPROCESS serviceProcess;

} FLOCK_DEVICE_DATA, *PFLOCK_DEVICE_DATA;

typedef struct _FLOCK_REQUEST_HEADER
{
	UCHAR signature[16]; // FLOCK_REQUEST_SIGNATURE
	DWORD version;
	DWORD requestId;
	DWORD length; // Body part size in bytes.

	union
	{
		DWORD context;
		DWORD counter;
	}params;

}FLOCK_REQUEST_HEADER, *PFLOCK_REQUEST_HEADER;

typedef struct _FLOCK_RESPONSE_HEADER
{
	UCHAR signature[16]; // FLOCK_RESPONSE_SIGNATURE
	DWORD version;
	DWORD flockStatus; // FLOCK_STATUS_XXX
	DWORD length; // Size of response body in bytes.

	union
	{
		DWORD context;
		DWORD requireLength;
	}params;

} FLOCK_RESPONSE_HEADER, *PFLOCK_RESPONSE_HEADER;

typedef struct _FLOCK_FILE_PATH
{
	ULONG filePathLength; // in bytes.
	WCHAR filePath[1]; // It can not include the last zero symbol.
} FLOCK_FILE_PATH, *PFLOCK_FILE_PATH;

typedef struct _FLOCK_REQUEST_MARK_FILE
{
	FLOCK_META info;
	ULONG filePathLength; // in bytes.
	WCHAR filePath[1];
}FLOCK_REQUEST_MARK_FILE, *PFLOCK_REQUEST_MARK_FILE;

typedef struct _FLOCK_REQUEST_MARK
{
	UCHAR flockId[16]; // unique id.

	BOOLEAN toSet; // TRUE if need to raise a flag, remove means remove the flag.
	ULONG flockFlag; // FLOCK_FLAG_HIDE , FLOCK_FLAG_LOCK_ACCESS, FLOCK_FLAG_XXX and etc.

}FLOCK_REQUEST_MARK, *PFLOCK_REQUEST_MARK;

typedef struct _FLOCK_REQUEST_QUERY_INFO
{
	UCHAR uniqueId[FLOCK_UNIQUE_ID_LENGTH];
}FLOCK_REQUEST_QUERY_INFO, *PFLOCK_REQUEST_QUERY_INFO;

typedef struct _FLOCK_RESPONSE_QUERY_INFO
{
	FLOCK_STORAGE_ENTRY info;
}FLOCK_RESPONSE_QUERY_INFO, *PFLOCK_RESPONSE_QUERY_INFO;

#pragma pack(pop)


//
// Returns pointer on main driver structure which keeps all important information.
//
PFLOCK_DEVICE_DATA FLockData();

PANSI_STRING FLockGetMetaAttributeName();


//
// Returns pointer to service process structure.
//
PEPROCESS FLockGetServiceProcess();

//
// Returns service process ID.
//
DWORD FLockGetServiceProcessId();

VOID FLockRegisterServiceProcess(
	__in PEPROCESS _process
	);

VOID FLockUnregisterServiceProcess();

EXTERN_C BOOLEAN FLockDriverPrepareStorage();

BOOLEAN FLockLogicNeedProtect(__in PUNICODE_STRING _ptrFsPath);

//
//	1. Opens file thought FltCreateFile(..)
//	2. Get PFILE_OBJET from HANDLE through ObReferenceObjectByHandle(..)
//	3. Reads FLock-meta using FLockFltReadFirstMeta(..)
//
BOOLEAN FLockFltOpenAndReadFirstMeta(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	//__in PFLT_CALLBACK_DATA _fltData,
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);

//
// Call when you are at <= APC_LEVEL only.
//
// Returns TRUE when finds FLock-meta on a some of path.
//
// The path could be a X:\work\protected\sara\docs\secrets.txt , but
// FLock-meta is only in one directory -  X:\work\protected, it means that this function should do
// the following steps:
//		1) Verify FLock-meta in X:\work\protected\sara\docs
//		2) Verify the same in X:\work\protected\sara
//		3) Verify ... in X:\work\protected
//		4) And finally find FLock-meta in 'X:\work\protected' directory, which is one of parents to secrets.txt.
//
BOOLEAN FLockFltSearchFirstMetaPath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in BOOLEAN _skipFirstFile,
	__out PFLOCK_META _readMetaInfo,
	__out PUNICODE_STRING _foundPath,
	__out NTSTATUS* _errorCode
	);

//
// Return file path in '_filePath' argument and
// do not forget to free memory of '_filePath->Buffer' through ExFreePool(..) later.
// 
// An example of file path: \Device\HarddiskVolume1\Windows\System32\notepad.exe
//
BOOLEAN FLockFltGetPath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	//__in PCFLT_RELATED_OBJECTS FltObjects,
	__out PUNICODE_STRING _filePath,
	__out NTSTATUS* _errorCode
	);

//
// This function reads FLock's EAs, doing following things:
//
//	1. Get file path by using FltGetFileNameInformation(..), FltParseFileNameInformation(..)
//	2. Reads FLock-meta using FLockFltOpenAndReadFirstMeta(..)
//	3. Copy string with path of the file if it has FLock-meta.
//
BOOLEAN FLockFltReadFirstMetaWithGetFilePath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__out PFLOCK_META _readMeta,
	__out_opt  PUNICODE_STRING _outFilePath,
	__out_opt NTSTATUS* _errorCode
	);

//
// Works faster then first one because
//	1. Does not allocate any additional memory - reads EAs right to buffer (local array on stack).
//	2. Before initiate a read request the function sets info about which EA to search.
//
BOOLEAN FLockReadFastFirstMeta(
	__in HANDLE _hFile,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);

//
// Does the same as FLockReadFastFirstMeta(..) but use filter manager functions.
// Use it only when current IRQL is < DISPATCH_LEVEL.
//
BOOLEAN FLockFltReadFirstMeta(
	__in PFLT_INSTANCE Instance,
	__in PFILE_OBJECT  FileObject,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);

//
// Writes flock meta information uses FILE_OBJECT for that and avoids receiving IRP_MJ_SET_EA request.
//
BOOLEAN FLockFltWriteFlockMeta(
	__in PFLT_INSTANCE _instance,
	__in PFILE_OBJECT  _fileObject,
	__in PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);

//
// Opens '_filePath' file path and searches 'FLOCK_META' in EAs, returns data in case the data is found.
//
BOOLEAN FLockFileReadFastFirstMeta(
	__in WCHAR* _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);

BOOLEAN FLockFileReadFastFirstMeta2(
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	);


//
// Return TRUE if file stream has 'FLOCK_META' attribute.
//
BOOLEAN FLockHasMeta(
	__in HANDLE _hFile
	);

// 
// Writes FLock meta info to file stream as an Extended Attribute.
//
BOOLEAN FLockWriteMeta(
	__in HANDLE _hFile,
	__out PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);

BOOLEAN FLockFileWriteMeta(
	__in WCHAR* _filePath,
	__out PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);

BOOLEAN FLockFileWriteMeta2(
	__in PUNICODE_STRING _filePath,
	__in PFLOCK_META _metaInfo,
	__out_opt NTSTATUS* _errorCode
	);

//
// Case sensitive.
//
BOOLEAN FLockEqualAnsiStrings(
	__in PANSI_STRING _first,
	__in PANSI_STRING _second
	);


// Handles all user-mode requests which was send through DeviceIoControl(..)
//
NTSTATUS FLockDeviceControlDispatcher(PDEVICE_OBJECT Fdo, PIRP Irp);

NTSTATUS FLockSuccessDispatcher(PDEVICE_OBJECT _deviceObject, PIRP _irp);


//
// Returns TRUE if the code executes in service process context.
//
BOOLEAN FLockAreWeInServiceProcessContext();

VOID FLockPrintMeta(
	__in PFLOCK_META _info
	);

BOOLEAN FLockHasBackslash(
	__in PUNICODE_STRING _str
	);

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
//
// File system filters.
//

FLT_PREOP_CALLBACK_STATUS flockPreWrite(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS flockPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS FLockPreFsControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostFsControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreMdlRead(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostMdlRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreQueryEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostQueryEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreRead(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreSetEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostSetEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreCreate(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreClose(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

//////////////////////////////////////////////////////////////////////////
// end //