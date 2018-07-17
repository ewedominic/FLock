//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"


extern ULONG gTraceFlags;



FLT_PREOP_CALLBACK_STATUS FLockPreQueryEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

// 	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
// 	{
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	// Do not handle that request if we are in context of service process.
	// Service process can do whatever it wants.
	//
	if (FLockAreWeInServiceProcessContext())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - this is a service process context, do not process it.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

// 	if (Data->Iopb->TargetFileObject){
// 		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject)){
// 			return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 		}
// 	}

	//return FLT_PREOP_SUCCESS_NO_CALLBACK;
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	//return FLT_PREOP_SYNCHRONIZE;
}



//
// This operation handler can be called at IRQL >= DISPATCH_LEVEL, because pre-operation handler returns FLT_PREOP_SUCCESS_WITH_CALLBACK,
// but not FLT_PREOP_SYNCHRONIZE and it works good despite on it. That is we do not touch paged memory here (in post-operation handler).
//

FLT_POSTOP_CALLBACK_STATUS FLockPostQueryEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

// 	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
// 	{
// 		return FLT_POSTOP_FINISHED_PROCESSING;
// 	}

	//PANSI_STRING flockMetaName = FLockGetMetaAttributeName();

	PVOID bufferEAs = Data->Iopb->Parameters.QueryEa.EaBuffer;
	ULONG bufferEAsLength = Data->Iopb->Parameters.QueryEa.Length;
	PMDL mdlEAs = Data->Iopb->Parameters.QueryEa.MdlAddress;
	BOOLEAN thisIsAnMdl = FALSE;

	if ((bufferEAs == NULL) && (mdlEAs != NULL))
	{
		thisIsAnMdl = TRUE;
	}

	if (bufferEAs == NULL)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: output buffer is empty.\n", __FUNCTION__));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	for (PFILE_FULL_EA_INFORMATION current = (PFILE_FULL_EA_INFORMATION)bufferEAs, prev = NULL; ;)
	{
		//
		// 1. At first we should decide - does it require to hide that extended attribute?
		//

		BOOLEAN requireHide = FALSE;

		//
		// Save pointer on first unreferenced object.
		//
		if (prev == NULL){
			prev = current;
		}

		if (current->EaNameLength == FLOCK_META_NAME_SIZE)
		{
			ANSI_STRING currentEaName = { 0 };
			currentEaName.Length = current->EaNameLength;
			currentEaName.MaximumLength = current->EaNameLength;
			currentEaName.Buffer = current->EaName;

			ANSI_STRING flockMetaName = { 0 };
			flockMetaName.Buffer = FLOCK_META_NAME;
			flockMetaName.Length = FLOCK_META_NAME_SIZE;
			flockMetaName.MaximumLength = FLOCK_META_NAME_SIZE;

			requireHide = FLockEqualAnsiStrings(&flockMetaName, &currentEaName);
		}

		//
		// 2. Hide the entry if it's need.
		//

		if (requireHide)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: require to process flock-meta.\n", __FUNCTION__));

			//
			// This is a flock-meta EAs. We can do following things:
			//		- Change name of an extended attribute;
			//		- Remove an attribute from the list;
			//		- Reject request.
			//

			//
			// Erase value's data.
			//

			PUCHAR border = ((PUCHAR)bufferEAs) + bufferEAsLength;

			if (current->NextEntryOffset){
				border = ((PUCHAR)current) + current->NextEntryOffset;
			}

			if (current->EaValueLength){
				ULONG valueLength = current->EaValueLength;
				PUCHAR eaValueBegin = (PUCHAR)(current->EaName + (current->EaNameLength + 1));
				if ( (eaValueBegin + current->EaValueLength) > border ) {
					valueLength = border - eaValueBegin;
				}

				RtlZeroMemory(eaValueBegin, valueLength);
			}

			//if (current->EaNameLength){
			//	ULONG nameLength = current->EaNameLength;
			//	PUCHAR eaNameBegin = (PUCHAR)current->EaName;
			//	if ((eaNameBegin + current->EaNameLength) > border) {
			//		nameLength = border - eaNameBegin;
			//	}
			//	RtlZeroMemory(current->EaName, nameLength);
			//}

			//
			// I'm not sure about that call, but it's better to do than not! 
			// Because actually we just changed the original data.
			//

			FltIsCallbackDataDirty(Data);

			if (prev == current)
			{
				if (current->NextEntryOffset)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: move entries to current position.\n", __FUNCTION__));

					PUCHAR nextEntryAddress = ((PUCHAR)current) + current->NextEntryOffset;
					ULONG sizeOfDataToMove = ((PUCHAR)bufferEAs + bufferEAsLength) /* end of buffer */ - ((PUCHAR)nextEntryAddress) /* next entry */;

					RtlCopyMemory(current, nextEntryAddress, sizeOfDataToMove);

					// Go to next iteration.
					prev = NULL;
					continue;
				}
				else
				{
					//
					// This is a case when we have single entry in the EAs list.
					//

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: change the name.\n", __FUNCTION__));

					//
					// Change name to the attribute on fake name.
					//
					RtlZeroMemory(current->EaName, current->EaNameLength);
					RtlCopyMemory(current->EaName, FLOCK_FAKE_META_NAME, FLOCK_FAKE_META_NAME_SIZE);

					//Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					//return FLT_PREOP_COMPLETE;
					//Data->Iopb->Parameters.QueryEa.Length = 0;
				}
			}
			else
			{
				if (current->NextEntryOffset)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: set prev to next.\n", __FUNCTION__));

					//
					// Calculate offset to next element for previous entry.
					// That next element actually is an element which is the next for current (hiding) element. 
					//

					ULONG offsetToNextAfterUs = ((ULONG)(((PUCHAR)current) - ((PUCHAR)prev))) + current->NextEntryOffset;
					// And I do not change here nothing with aligning.

					prev->NextEntryOffset = offsetToNextAfterUs;

					RtlZeroMemory(current, sizeof(FILE_FULL_EA_INFORMATION));
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: set prev to 0.\n", __FUNCTION__));

					//
					// We have previous entry, but have no next.
					// Mark previous as last and write zeros for our (hiding) entry.
					//

					prev->NextEntryOffset = 0;

					RtlZeroMemory(current, sizeof(FILE_FULL_EA_INFORMATION));
				}
			}
		}
		else
		{
			prev = current;
		}

		//
		// Go to next iteration.
		//

		if (current->NextEntryOffset != 0){
			current = (PFILE_FULL_EA_INFORMATION)(((PUCHAR)current) + current->NextEntryOffset);
		}
		else {
			break;
		}

	} // end for(..){.

	return FLT_POSTOP_FINISHED_PROCESSING;
}
