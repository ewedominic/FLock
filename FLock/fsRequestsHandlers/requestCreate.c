//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"
#include "../FLockStorage.h"

extern ULONG gTraceFlags;
extern FLOCK_DEVICE_DATA g_flockData;

//
// Minifilter drivers should not return FLT_PREOP_SYNCHRONIZE for create operations, because these operations
// are already synchronized by the filter manager.If a minifilter driver has registered preoperation and postoperation
// callback routines for IRP_MJ_CREATE operations, the post - create callback routine is called at IRQL =
// PASSIVE_LEVEL, in the same thread context as the pre - create callback routine.
//


FLT_PREOP_CALLBACK_STATUS FLockPreCreate(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	FLOCK_META fm = { 0 };

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: we don't want to handle FatIo.\n", __FUNCTION__));
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - its a page file opening.", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

// 	if (!FLockStorageHasLockedUserObjects())
// 	{
// 		//
// 		// There is no one object which should be protected for an access.
// 		//
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}

	if (BooleanFlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - this is a volume open request.", __FUNCTION__));
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->Iopb->TargetFileObject){
		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject)){
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is page file opening. Ignore.\n", __FUNCTION__));
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	} else {
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning it's no FILE_OBJECT.\n", __FUNCTION__));
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is not IRP based operation.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	ULONG	createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
	ULONG	createOptions = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
	ULONG	desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

	//if (BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
	//	//Эта операция не поддерживатеся
	//	goto _access_denied;
	//}

	//
	// If it the FILE_DELETE_ON_CLOSE flag is set than we should handle that request here in pre-operation handler.
	// If the flag is not set then we need left all work to post-operation handler.
	//
	if ( BooleanFlagOn(desiredAccess, FILE_DELETE_ON_CLOSE) )
	{
		//
		// Later we will handle verification of the access request through FLockCache.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: read-flocks.\n", __FUNCTION__));

		UNICODE_STRING filepath = { 0 };
		BOOLEAN result = FLockFltReadFirstMetaWithGetFilePath(
			g_flockData.filterHandle,
			Data->Iopb->TargetInstance,
			Data,
			&fm,
			&filepath,
			&status);

		if (result)
		{
			//
			// Verify an access policy.
			//

			BOOLEAN lockAccessPolicy = FALSE;

			//
			// Search data in our storage with access policies.
			//
			if (FLockStorageIsLoaded()){
				lockAccessPolicy = FLockStorageVerifyLock(fm.uniqueId);
			}

			// For first time we use that.
			if (!lockAccessPolicy){
				lockAccessPolicy = BooleanFlagOn(fm.flags, FLOCK_FLAG_LOCK_ACCESS);
			}

			if (lockAccessPolicy)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: access was locked to %wZ\n", __FUNCTION__, &filepath));

				if (filepath.Buffer) {
					ExFreePool(filepath.Buffer);
				}

				//
				// Lock an access to a file.
				//

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				return FLT_PREOP_COMPLETE;
			}
			else
			{
				//
				// Free memory for a file path buffer.
				//

				if (filepath.Buffer) {
					ExFreePool(filepath.Buffer);
				}
			}
		}
		else
		{
			//
			// Couldn't read flock-meta from a file or just not found.
			//
		}

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	//
	// Minifilter drivers should not return FLT_PREOP_SYNCHRONIZE for create operations, because these operations
	// are already synchronized by the filter manager.If a minifilter driver has registered preoperation and postoperation
	// callback routines for IRP_MJ_CREATE operations, the post - create callback routine is called at IRQL =
	// PASSIVE_LEVEL, in the same thread context as the pre - create callback routine.
	//

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	PAGED_CODE();

	NTSTATUS status;
	FLOCK_META fm = { 0 };
	BOOLEAN result = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: read flock.\n", __FUNCTION__));

	result = FLockFltReadFirstMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &fm, &status);

	if (result) // We found an FLock-meta.
	{
		BOOLEAN lockAccessPolicy = FALSE;

		//
		// Search data in our storage with access policies.
		//

		if (FLockStorageIsLoaded()){
			lockAccessPolicy = FLockStorageVerifyLock(fm.uniqueId);
		}

		// For first time we use that.
		if (!lockAccessPolicy){
			lockAccessPolicy = BooleanFlagOn(fm.flags, FLOCK_FLAG_LOCK_ACCESS);
		}

		if (lockAccessPolicy)
		{
			//
			// Query file name to print more details.
			//

			UNICODE_STRING filepath = { 0 };
			BOOLEAN hasFilePath = FLockFltGetPath(g_flockData.filterHandle, Data->Iopb->TargetInstance, Data, &filepath, &status);

			if (hasFilePath)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: There was an access to - %wZ\n", __FUNCTION__, &filepath));
				ExFreePool(filepath.Buffer);
				RtlZeroMemory(&filepath, sizeof(filepath));
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - couldn't find file path.\n", __FUNCTION__));
			}

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - an access was locked\n", __FUNCTION__));

			//
			// 	FltCancelFileOpen must be called before any handles are created for the file.
			// 	Callers can check the Flags member of the FILE_OBJECT structure that the FileObject parameter points to.
			// 	If the FO_HANDLE_CREATED flag is set, this means that one or more handles have been created for the file, so it is not safe to call FltCancelFileOpen.
			//

			//
			//	Callers of FltCancelFileOpen must be running at IRQL PASSIVE_LEVEL. However, it is safe for minifilter drivers
			//	to call this routine from a post - create callback routine, because post - create callback routines are guaranteed
			//	to be called at IRQL PASSIVE_LEVEL, in the context of the thread that originated the IRP_MJ_CREATE request.
			//
			// * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/fltkernel/nf-fltkernel-fltcancelfileopen
			//

			Data->IoStatus.Status = STATUS_ACCESS_DENIED;

			FltCancelFileOpen(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject);
			FltIsCallbackDataDirty(Data);
		}
	}
	else // Need to make deep search.
	{
		//
		// Start search for FLok-meta in parent paths.
		//

// 		BOOLEAN skipCurrent = TRUE;
// 
// 		if (Data->Iopb->TargetFileObject){
// 			if (!(Data->Iopb->TargetFileObject->Flags & FO_HANDLE_CREATED)) {
// 				skipCurrent = FALSE;
// 			}
// 		}

// 		result = FLockFltSearchFirstMetaPath(
// 			g_flockData.filterHandle,
// 			Data->Iopb->TargetInstance,
// 			Data,
// 			FltObjects,
// 			skipCurrent,
// 			&fm,
// 			&fm/* temporary!! */,
// 			&status);
// 
// 		if (result)
// 		{
// 			if (FLockStorageVerifyLock(fm.uniqueId))
// 			{
// 				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - FLock-meta search succeeded.\n", __FUNCTION__));
// 
// 				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
// 
// 				FltCancelFileOpen(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject);
// 				FltIsCallbackDataDirty(Data);
// 			}
// 		}
// 		else
// 		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: FLock-meta search was not found.\n", __FUNCTION__));
// 		}

	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}
