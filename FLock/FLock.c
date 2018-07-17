/*++

Module Name:

    FLock.c

Abstract:

    This is the main module of the FLock miniFilter driver.

Environment:

    Kernel mode

Author:
	
	Burlutsky Stanislav (burlickij@gmail.com)

Creation time:
	
	12.05.2018 21:10:12

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "flock.h"
#include "FLockStorage.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


ULONG_PTR OperationStatusCtx = 1;

FLOCK_DEVICE_DATA g_flockData;

ULONG gTraceFlags = 0;

ANSI_STRING g_flockMetaName;
char* dataw = FLOCK_META_NAME;


/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

void DriverUnload(
	_In_ PDRIVER_OBJECT pDrvObj
	);

NTSTATUS
FLockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FLockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FLockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FLockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FLockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FLockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
FLockOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
FLockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FLockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
FLockDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
//#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FLockUnload)
#pragma alloc_text(PAGE, FLockInstanceQueryTeardown)
#pragma alloc_text(PAGE, FLockInstanceSetup)
#pragma alloc_text(PAGE, FLockInstanceTeardownStart)
#pragma alloc_text(PAGE, FLockInstanceTeardownComplete)
#endif

//
//  Operation registration
//	Here we notify filter manager about which IRP packets we want to process
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    {
		IRP_MJ_CREATE,
		0,
		FLockPreCreate,
		FLockPostCreate,
		NULL
	},

	{
		IRP_MJ_DIRECTORY_CONTROL,
		0,
		FLockPreDirectoryControl,
		FLockPostDirectoryControl,
		NULL
	},

	{
		IRP_MJ_QUERY_EA,
		0,
		FLockPreQueryEa,
		FLockPostQueryEa,
		NULL
	},

	{
		IRP_MJ_SET_EA,
		0,
		FLockPreSetEa,
		FLockPostSetEa,
		NULL
	},

// 	{
// 		IRP_MJ_FILE_SYSTEM_CONTROL,
// 		0,
// 		FLockPreFsControl,
// 		FLockPostFsControl,
// 		NULL
// 	},

//     { IRP_MJ_CLOSE,
//       0,
//       flockPreClose,
//       flockPostClose },
// 
//     { IRP_MJ_READ,
//       0,
//       flockPreRead,
//       flockPostRead },
// 
//     { IRP_MJ_WRITE,
//       0,
//       flockPreWrite,
//       flockPostWrite },
// 
//     { IRP_MJ_QUERY_INFORMATION,
//       0,
//       flockPreQueryInformation,
//       flockPostQueryInformation },
// 
//     { IRP_MJ_SET_INFORMATION,
//       0,
//       FLockPreSetInformation,
//       FLockPostSetInformation },
// 
// 
// 	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
// 	  0,
// 	  FLockPreOperation,
// 	  FLockPostOperation },
// 
// 	{ IRP_MJ_SET_VOLUME_INFORMATION,
// 	  0,
// 	  FLockPreOperation,
// 	  FLockPostOperation },
//
// 	  { IRP_MJ_FLUSH_BUFFERS,
// 	  0,
// 	  FLockPreOperation,
// 	  FLockPostOperation },
//
// 	  { IRP_MJ_CREATE_NAMED_PIPE,
// 	  0,
// 	  FLockPreOperation,
// 	  FLockPostOperation },
//
//     { IRP_MJ_DEVICE_CONTROL,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_INTERNAL_DEVICE_CONTROL,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
//
//     { IRP_MJ_SHUTDOWN,
//       0,
//       FLockPreOperationNoPostOperation,
//       NULL },                               //post operations not supported
//
//     { IRP_MJ_LOCK_CONTROL,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_CLEANUP,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_CREATE_MAILSLOT,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_QUERY_SECURITY,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_SET_SECURITY,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_QUERY_QUOTA,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_SET_QUOTA,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_PNP,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_RELEASE_FOR_MOD_WRITE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_RELEASE_FOR_CC_FLUSH,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_NETWORK_QUERY_OPEN,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_MDL_READ,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

//     { IRP_MJ_MDL_READ_COMPLETE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_PREPARE_MDL_WRITE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_MDL_WRITE_COMPLETE,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_VOLUME_MOUNT,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },
// 
//     { IRP_MJ_VOLUME_DISMOUNT,
//       0,
//       FLockPreOperation,
//       FLockPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    FLockUnload,                           //  MiniFilterUnload

    FLockInstanceSetup,                    //  InstanceSetup
    FLockInstanceQueryTeardown,            //  InstanceQueryTeardown
    FLockInstanceTeardownStart,            //  InstanceTeardownStart
    FLockInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

PFLOCK_DEVICE_DATA FLockData()
{
	return &g_flockData;
}

PANSI_STRING FLockGetMetaAttributeName()
{
	return &g_flockMetaName;
}

VOID FLockRegisterServiceProcess(
	__in PEPROCESS _process
	)
{
	// ... lock ...

	FLockData()->serviceProcess = _process;
	FLockData()->serviceProcessId = (DWORD)PsGetProcessId(_process);

	// ... unlock ...
}


VOID FLockUnregisterServiceProcess()
{
	// ... lock ...

	FLockData()->serviceProcess = NULL;
	FLockData()->serviceProcessId = 0;

	// ... unlock ...
}


PEPROCESS FLockGetServiceProcess()
{
	return g_flockData.serviceProcess;
}

DWORD FLockGetServiceProcessId()
{
	return g_flockData.serviceProcessId;
}


BOOLEAN FLockAreWeInServiceProcessContext()
{
	DWORD servPid = FLockGetServiceProcessId();
	PEPROCESS servProcess = FLockGetServiceProcess();
	PEPROCESS currentProcess = PsGetCurrentProcess();
	DWORD currentPid = PsGetProcessId(currentProcess);

	return (servProcess == currentProcess) && (servPid == currentPid);
}

VOID FLockPrintMeta(
	__in PFLOCK_META _info
	)
{
	if (_info)
	{
		PUCHAR p = _info->uniqueId;
		PUCHAR k = _info->signature;

		DbgPrint("FLock!%s: .version = 0x%x .flags = 0x%x .uniqieId = %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x, .signature = %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n",
			__FUNCTION__,
			_info->version,
			_info->flags,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
			k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]
			);
	}
}

void FLockTestHide()
{
	NTSTATUS status = STATUS_SUCCESS;
	FLOCK_META fmDir = { 0 }, fmFile = { 0 };
	WCHAR* volumePath = L"\\??\\c:\\";
	WCHAR* rootFile = L"\\??\\c:\\flock_ea.txt";

	WCHAR* dirPath = L"\\??\\c:\\flock_ea";
	WCHAR* filePath = L"\\??\\c:\\flock_ea\\file.txt";
	
	WCHAR* root2ndVolumeFilePath = L"\\??\\e:\\$10msecret_ea.txt";
	WCHAR* root2ndVolume = L"\\??\\e:\\";

	UCHAR signatureMeta[16] = FLOCK_META_SIGNATURE;

	fmDir.uniqueId[0] = 0xaf;
	fmDir.version = 1;
	fmDir.flags = FLOCK_FLAG_HAS_FLOCKS;
	memcpy(fmDir.signature, signatureMeta, sizeof(signatureMeta));

	FLockFileWriteMeta(dirPath, &fmDir, &status);
	FLockFileWriteMeta(volumePath, &fmDir, &status);

	fmFile.uniqueId[0] = 0xFF;
	fmFile.version = 1;
	fmFile.flags = FLOCK_FLAG_HIDE /*| FLOCK_FLAG_LOCK_ACCESS*/;
	memcpy(fmFile.signature, signatureMeta, sizeof(signatureMeta));
	
	//FLockFileWriteMeta(filePath, &fmFile, &status);

	fmFile.flags = FLOCK_FLAG_HIDE | FLOCK_FLAG_LOCK_ACCESS;
	FLockFileWriteMeta(rootFile, &fmFile, &status);

	//
	// For second volume.
	//

	fmFile.flags = FLOCK_FLAG_HAS_FLOCKS;
	FLockFileWriteMeta(root2ndVolume, &fmFile, &status);

	fmFile.flags = FLOCK_FLAG_HIDE /*| FLOCK_FLAG_LOCK_ACCESS*/;
	FLockFileWriteMeta(root2ndVolumeFilePath, &fmFile, &status);
}

void FLockTest()
{
	BOOLEAN result = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	FLOCK_META fm = { 0 };
	WCHAR* filePath = L"\\??\\c:\\flock_ea.txt";
	UCHAR signatureMeta[16] = FLOCK_META_SIGNATURE;

	fm.uniqueId[0] = 0xFF;
	fm.version = 1;
	fm.flags = FLOCK_FLAG_LOCK_ACCESS;
	memcpy(fm.signature, signatureMeta, sizeof(signatureMeta));

	result = FLockFileWriteMeta(filePath, &fm, &status);

	if (result)
	{
		result = FLockFileReadFastFirstMeta(filePath, &fm, &status);

		if (result)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - EAs was read.\n", __FUNCTION__));
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Failed - EAs was not read. Status is 0x%x (%d)\n", __FUNCTION__, status, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Failed - can't write FLock meta.\n", __FUNCTION__));
	}
}

EXTERN_C BOOLEAN FLockDriverPrepareStorage()
{
	BOOLEAN storageLoadedSucessfully = FALSE;

// 	if (FLockStorageIsInitialized() == FALSE) {
// 		if (FLockStorageInit()){
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s storage is initialized.\n", __FUNCTION__));
// 		} else {
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s error - couldn't initialize flocks storage.\n", __FUNCTION__));
// 			return FALSE;
// 		}
// 	}

	if (FLockStorageInit()){
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s storage is initialized.\n", __FUNCTION__));
	}
	else {
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s error - couldn't initialize flocks storage.\n", __FUNCTION__));
		return FALSE;
	}

	if (FLockStorageOpen())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s storage is loaded.\n", __FUNCTION__));

		if (FLockStorageLoad())
		{
			storageLoadedSucessfully = FLockStorageImport();
			if (storageLoadedSucessfully == FALSE)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s error - couldn't import data.\n", __FUNCTION__));

				//
				// After calling this function the storage file with all data comes available to every body!
				//
				FLockStorageUnload();

				//FLockStorageDeinitialize();
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s FLockStorageLoad failed.\n", __FUNCTION__));

			//FLockStorageDeinitialize();
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s error - storage was not loaded.\n", __FUNCTION__));

		//FLockStorageDeinitialize();
	}

	return storageLoadedSucessfully;
}

EXTERN_C VOID FLockDriverCloseStorage()
{
	if (FLockStorageIsOpened())
	{
		FLockStorageExportOnDisk();

		FLockStorageFlushMapped();

		FLockStorageUnload();

		FLockStorageDeinitialize();
	}
}


/*************************************************************************
	MiniFilter entry point.
*************************************************************************/


NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
)
/*++

	Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.

	Arguments:

		DriverObject - Pointer to driver object created by the system to
		represent this driver.

		RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

	Return Value:

		Routine can return non success error codes.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;

	RtlZeroMemory(&g_flockData, sizeof(FLOCK_DEVICE_DATA));

	RtlInitAnsiString(&g_flockMetaName, dataw);

	//
	// Print maximum information.
	//

	gTraceFlags |= PTDBG_TRACE_FULL;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: registry path is %wZ\n", __FUNCTION__, RegistryPath));

	//FLockTest();
	FLockTestHide();

	//DriverObject->DriverUnload = DriverUnload; // Uncomment for tests only.

	//return STATUS_UNSUCCESSFUL;

	//
	// Initialize FLock storage.
	//

// 	BOOLEAN storageLoadedSucessfully = FLockDriverPrepareStorage();
// 	if (!storageLoadedSucessfully)
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - the storage was not prepared to work with.\n", __FUNCTION__));
// 
// 		//return STATUS_DRIVER_UNABLE_TO_LOAD;
// 		return STATUS_UNSUCCESSFUL;
// 	}

	//return STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&g_flockData.deviceNameUnicodeString, FLOCK_DEVICE_NAME);
	RtlInitUnicodeString(&g_flockData.deviceLinkUnicodeString, FLOCK_DEVICE_LINK);

	status = IoCreateDevice(DriverObject,
		0,
		&g_flockData.deviceNameUnicodeString,
		FLOCK_DEVICE,
		FILE_DEVICE_SECURE_OPEN, // 0
		FALSE, // TRUE
		&g_flockData.deviceObject);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to create device, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		return status;
	}

	status = IoCreateSymbolicLink(&g_flockData.deviceLinkUnicodeString, &g_flockData.deviceNameUnicodeString);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to create symbolic link, status code is 0x%x (%d)\n", __FUNCTION__, status, status));

		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	g_flockData.driverObject = DriverObject;

	//
	// Print current status - everything is ok, FLock device object was created successfully. 
	//

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Device was successfully created", __FUNCTION__));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_flockData.filterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status))
	{
		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(g_flockData.filterHandle);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to start the mini-filter, status code is 0x%x (%d)\n", __FUNCTION__, status, status));

			FltUnregisterFilter(g_flockData.filterHandle);
			IoDeleteSymbolicLink(&g_flockData.deviceLinkUnicodeString);
			IoDeleteDevice(DriverObject->DeviceObject); // Remove all devices, but we created only one, it may confuse you.
			return status;
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to register the mini-filter, status code is 0x%x (%d)\n", __FUNCTION__, status, status));

		IoDeleteSymbolicLink(&g_flockData.deviceLinkUnicodeString);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	//
	// Register IRP handler. We have one handler on all requests.
	//

	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] =
	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = FLockSuccessDispatcher;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FLockDeviceControlDispatcher;

	//
	// User should have no an opportunity to unload the driver.
	//
	DriverObject->DriverUnload = DriverUnload; // Uncomment for tests only.

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Driver was successfully loaded and initialized.", __FUNCTION__));

	return status;
}

void DriverUnload(IN PDRIVER_OBJECT pDrvObj)
{
	UNREFERENCED_PARAMETER(pDrvObj);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Driver is going to be unloaded.", __FUNCTION__));

	//
	// All deinitialization should be here.
	//

	FLockDriverCloseStorage();
}

NTSTATUS
FLockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FLockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FLockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockInstanceTeardownStart: Entered\n") );
}


VOID
FLockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
FLockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: driver received request to unload.\n", __FUNCTION__));

	FltUnregisterFilter(g_flockData.filterHandle);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
FLockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (FLockDoRequestOperationStatus( Data ))
	{
        status = FltRequestOperationStatusCallback( Data,
                                                    FLockOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("FLock!FLockPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
FLockOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FLock!FLockOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
FLockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FLockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FLock!FLockPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FLockDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
